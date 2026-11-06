"""Quiet daemon recorder: same counts and decoder state as RedactingRecorder; synthetic bytes only."""
from collections import Counter
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from conn_frames import Frame,PAD_BYTE,encode
import conn_transfer
import kms_daemon_live as daemon
import rtsp_udp_play as play
import tcp_control as tcp
from tunnel_probe import Link


def media(transaction,payload_bytes=1316):
    rtp=struct.pack(">BBHII",0x80,33,transaction&0xffff,transaction*3000,7)
    payload=rtp+b"\x47"*(payload_bytes-12)
    body=tcp._DATA.pack(17,play.RTP_CONFIG,2,play.RTP_PORT,50000,play.RTP_PORT,play.RTP_PORT,
                        tcp._DATA_HEADER_BYTES,len(payload))+payload
    return encode(Frame(5,1,transaction,body))


def sized(size,transaction):
    # Non-UDP Data request of an exact frame size, as in test_conn_transfer.
    return encode(Frame(5,1,transaction,b"b"*(size-20)))


def reads(transfer):
    return [transfer[i:i+512] for i in range(0,len(transfer),512)]


def stream():
    """(direction,data) records covering every recorder branch except a parse failure."""
    batch=sized(1384,1)+sized(1008,2)+sized(1384,3)
    assert len(batch)%64==0
    transfers=[batch+bytes([PAD_BYTE]),media(4),encode(Frame(7,3,None,b"note")),
               encode(Frame(2,2,5,b"\0"*8)),media(6,1316+64)]
    records=[("in",chunk) for transfer in transfers for chunk in reads(transfer)]
    ack=tcp.data_ack(9,1384)
    return records+[("out",encode(ack)),("out_zlp",b""),("ack_suppressed",encode(ack))]


def recorder(kind,quiet):
    written=[]
    log=daemon.DaemonLog(lambda event,**fields:written.append(dict(event=event,**fields)))
    log.quiet=quiet
    record=kind(log,65536)
    record.decoder=conn_transfer.TransferDecoder(65536)
    return record,log,written


def state(record):
    decoder=record.decoder
    return (record.failed,bytes(decoder._buffer),decoder._expected,decoder._pad_pending,
            decoder._failed,decoder.transfer_bytes,decoder.transfer_pads)


class Tests(unittest.TestCase):
    def run_both(self,records,quiet):
        results=[]
        for kind in (play.RedactingRecorder,daemon.DaemonRecorder):
            record,log,written=recorder(kind,quiet)
            for direction,data in records:
                record(direction,data)
            results.append((Counter(log.suppressed),written,state(record)))
        return results

    def test_quiet_counts_and_decoder_state_match_the_redacting_recorder(self):
        original,quiet=self.run_both(stream(),quiet=True)
        self.assertEqual(quiet,original)
        counts,written,(failed,*_,pads)=quiet
        self.assertEqual(written,[])
        self.assertFalse(failed)
        self.assertEqual(pads,1)
        self.assertEqual(counts["usb_frame_in_data"],5)
        self.assertEqual(counts["usb_frame_in"],2)
        self.assertEqual(counts["usb_raw"],3)

    def test_quiet_parse_failure_counts_and_poisons_like_the_original(self):
        records=[("in",media(1)[:30]),("in",b"XXXX"+bytes(12)),("in",media(2))]
        original,quiet=self.run_both([("in",b"BAD!"+bytes(12))]+records,quiet=True)
        self.assertEqual(quiet,original)
        self.assertTrue(quiet[2][0])
        self.assertEqual(quiet[0]["usb_in_unparsed"],4)
        self.assertEqual(quiet[0]["usb_in_chunk"],1)

    def test_verbose_output_is_the_redacting_recorders(self):
        original,verbose=self.run_both(stream(),quiet=False)
        self.assertEqual(verbose,original)
        self.assertTrue(any(e["event"]=="usb_frame_in_data" and "payload_sha256" in e
                            for e in verbose[1]))

    def test_decoder_stays_in_step_when_quiet_ends_mid_frame(self):
        frames=[media(1),media(2),media(3)]
        chunks=[chunk for frame in frames for chunk in reads(frame)]
        split=len(reads(frames[0]))+1   # inside the second frame
        logs=[]
        for kind in (play.RedactingRecorder,daemon.DaemonRecorder):
            record,log,written=recorder(kind,quiet=True)
            for index,chunk in enumerate(chunks):
                log.quiet=index<split
                record("in",chunk)
            logs.append(written)
        self.assertEqual(logs[1],logs[0])
        data=[e for e in logs[1] if e["event"]=="usb_frame_in_data"]
        self.assertEqual(len(data),2)
        self.assertTrue(all("media_header" in e for e in data))

    def test_every_recorder_event_is_quiet(self):
        self.assertLessEqual(daemon.RECORDER_EVENTS,daemon.QUIET_EVENTS)

    def test_owner_installs_it_before_transfer_sessions_replace_decoders(self):
        class FakeSession:
            def __init__(self,link,*args,log,**kwargs):
                self.log,self.max_frame_bytes=log,65536
                self.decoder=SimpleNamespace(max_frame_bytes=65536)
                link.record=play.RedactingRecorder(log,65536)
        owner=daemon.DaemonOwner.__new__(daemon.DaemonOwner)
        owner.sink=owner.stop_file=owner.input_fifo=None
        owner.on_streaming=lambda:None
        link=Link(SimpleNamespace(),TimeoutError)
        with patch.object(daemon,"DaemonSession",FakeSession):
            session=conn_transfer.TransferSessions(owner).session(
                link,1,65536,daemon.long.MAX_RECEIVE_BYTES,log=lambda event,**fields:None)
        self.assertIs(type(link.record),daemon.DaemonRecorder)
        self.assertIs(link.record.log,session.log)
        self.assertIsInstance(link.record.decoder,conn_transfer.TransferDecoder)
        self.assertIsInstance(session.decoder,conn_transfer.TransferDecoder)
        self.assertIs(owner.reader.link,link)


if __name__=="__main__":
    unittest.main()
