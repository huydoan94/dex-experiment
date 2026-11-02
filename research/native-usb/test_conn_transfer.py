"""Per-transfer pad handling and decoder installation; synthetic bytes only."""
from types import SimpleNamespace
import unittest

from conn_frames import Decoder,Frame,PAD_BYTE,encode
import conn_transfer as t
import duplex_link
from test_duplex_link import FifoDevice
from tunnel_probe import Link


def frame(size,transaction,last=b"x"):
    body=b"b"*(size-21)+last
    return encode(Frame(5,1,transaction,body))


def reads(transfer):
    # One USB transfer as the duplex reader sees it: 512-byte reads, then the short rest.
    return [transfer[i:i+512] for i in range(0,len(transfer),512)]


def decode(decoder,transfers):
    frames=[]
    for transfer in transfers:
        for chunk in reads(transfer):
            frames+=decoder.feed(chunk)
    return frames


class Tests(unittest.TestCase):
    def test_batched_transfer_pad_from_live_run_is_dropped(self):
        batch=frame(1384,1)+frame(1008,2)+frame(1384,3)
        self.assertEqual(len(batch)%64,0)
        transfers=[batch+bytes([PAD_BYTE]),frame(1384,4)]
        with self.assertRaisesRegex(ValueError,"invalid CONN header"):
            decode(Decoder(65536),transfers)
        decoder=t.TransferDecoder(65536)
        self.assertEqual([f.transaction for f in decode(decoder,transfers)],[1,2,3,4])
        self.assertEqual(decoder.transfer_pads,1)

    def test_single_frame_pad_still_uses_base_rule(self):
        decoder=t.TransferDecoder(65536)
        transfers=[frame(1024,1)+bytes([PAD_BYTE]),frame(100,2)]
        self.assertEqual([f.transaction for f in decode(decoder,transfers)],[1,2])
        self.assertEqual(decoder.transfer_pads,0)

    def test_frame_ending_in_pad_byte_is_not_truncated(self):
        # 65 = 64+1 and the last byte is 0x5a, but it is inside a frame body.
        decoder=t.TransferDecoder(65536)
        data=frame(65,1,last=bytes([PAD_BYTE]))
        frames=decode(decoder,[data,frame(100,2)])
        self.assertEqual([f.transaction for f in frames],[1,2])
        self.assertEqual(frames[0].body[-1],PAD_BYTE)
        self.assertEqual(decoder.transfer_pads,0)

    def test_pad_byte_without_multiple_of_64_still_fails_closed(self):
        decoder=t.TransferDecoder(65536)
        with self.assertRaisesRegex(ValueError,"invalid CONN header"):
            decode(decoder,[frame(100,1)+bytes([PAD_BYTE]),frame(100,2)])

    def test_full_packet_reads_do_not_end_a_transfer(self):
        # 1024+1 bytes: two full reads then one byte; only the final short read ends it.
        decoder=t.TransferDecoder(65536)
        batch=frame(512,1)+frame(512,2)
        self.assertEqual([f.transaction for f in decode(decoder,[batch+bytes([PAD_BYTE]),frame(100,3)])],[1,2,3])
        self.assertEqual(decoder.transfer_bytes,0)
        self.assertEqual(decoder.transfer_pads,0)

    def test_lone_pad_read_after_packet_aligned_batch_is_dropped(self):
        # 1000+2584=3584=7*512: seven full reads, then the pad alone; 2584 is not a multiple of 64.
        decoder=t.TransferDecoder(65536)
        batch=frame(1000,1)+frame(2584,2)
        self.assertEqual(len(reads(batch+bytes([PAD_BYTE])))-1,7)
        self.assertEqual([f.transaction for f in decode(decoder,[batch+bytes([PAD_BYTE]),frame(100,3)])],[1,2,3])
        self.assertEqual(decoder.transfer_pads,1)

    def test_factory_replaces_protocol_and_recorder_decoders_before_io(self):
        link=SimpleNamespace(record=SimpleNamespace(decoder=Decoder(4096)))
        session=SimpleNamespace(decoder=Decoder(8192))
        owner=SimpleNamespace(session=lambda *a,**kw:session)
        sessions=t.TransferSessions(owner)
        self.assertIs(sessions.session(link,1,2),session)
        self.assertIsInstance(session.decoder,t.TransferDecoder)
        self.assertIsInstance(link.record.decoder,t.TransferDecoder)
        self.assertEqual((session.decoder.max_frame_bytes,link.record.decoder.max_frame_bytes),(8192,4096))
        self.assertEqual(sessions.pads(),[0,0])

    def test_protocol_and_recorder_decode_same_duplex_reads(self):
        transfer=frame(1384,1)+frame(1008,2)+frame(1384,3)+bytes([PAD_BYTE])
        device=FifoDevice(reads(transfer)+reads(frame(1384,4)))
        events,result=[],{}
        util=SimpleNamespace(claim_interface=lambda *a:None,release_interface=lambda *a:None,
                             dispose_resources=lambda *a:None)
        owner=duplex_link.UsbOwner(util,result)
        sessions=t.TransferSessions(owner)
        link=Link(device,TimeoutError)
        session=sessions.session(link,1,65536,65536,log=lambda event,**kw:events.append(event))
        frames=[]
        try:
            for _ in range(30):
                frames+=session.decoder.feed(link.read(512,200))
                if len(frames)==4:break
        finally:
            owner.release_interface(device,3);owner.dispose_resources(device)
        self.assertEqual([f.transaction for f in frames],[1,2,3,4])
        self.assertNotIn("usb_in_unparsed",events)
        self.assertEqual(events.count("usb_frame_in_data"),4)
        self.assertEqual(sessions.pads(),[1,1])

if __name__=="__main__":unittest.main()
