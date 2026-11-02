"""Receive-only metadata capture bounds and cleanup; no device access."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from conn_frames import encode
import queued_media_capture as c
from test_udp_play import datagram,SECRET


class FakeUtil:
    def __init__(self): self.calls=[]
    def claim_interface(self,d,i): self.calls.append(("claim",i))
    def release_interface(self,d,i): self.calls.append(("release",i))
    def dispose_resources(self,d): self.calls.append(("dispose",))

class FakeDevice:
    def __init__(self,chunks): self.chunks=iter(chunks);self.calls=[]
    def get_active_configuration(self):return object()
    def is_kernel_driver_active(self,i):return False
    def read(self,endpoint,size,timeout):
        self.calls.append((endpoint,size,timeout))
        item=next(self.chunks,TimeoutError())
        if isinstance(item,Exception):raise item
        return item
    def write(self,*a,**kw):raise AssertionError("bulk OUT forbidden")


class Tests(unittest.TestCase):
    def run_capture(self,chunks):
        device,util,result=FakeDevice(chunks),FakeUtil(),{}
        with tempfile.TemporaryDirectory() as tmp,patch.object(c,"validate_config"),contextlib.redirect_stdout(io.StringIO()):
            try:
                c.capture(device,util,TimeoutError,Path(tmp),result,clock=lambda:0)
            except Exception as error:
                result["caught"]=type(error).__name__
            log=(Path(tmp)/"events.jsonl").read_text()
        return device,util,result,log

    def test_split_rtp_saved_only_as_headers_and_digests(self):
        raw=encode(datagram(1205,46002,19000,5))
        device,util,result,log=self.run_capture([raw[:50],raw[50:]])
        self.assertEqual(result["complete_frames"],1)
        self.assertEqual(result["raw_in_bytes"],len(raw))
        self.assertEqual(result["read_calls"],2)
        self.assertNotIn(SECRET.decode(),log)
        self.assertNotIn(SECRET.hex(),log)
        self.assertIn("payload_sha256",log)
        self.assertEqual(util.calls,[("claim",3),("release",3),("dispose",)])
        self.assertTrue(all(endpoint==0x85 and size==512 and timeout<=200 for endpoint,size,timeout in device.calls))

    def test_quiet_is_an_observation_and_cleanup_runs(self):
        _,util,result,log=self.run_capture([TimeoutError()])
        self.assertTrue(result["quiet_observed"])
        self.assertTrue(result["capture_completed"])
        self.assertEqual(result["raw_in_bytes"],0)
        self.assertEqual(util.calls[-2:],[("release",3),("dispose",)])

    def test_read_error_still_releases(self):
        _,util,result,log=self.run_capture([RuntimeError("synthetic")])
        self.assertEqual(result["caught"],"RuntimeError")
        self.assertNotIn("capture_completed",result)
        self.assertEqual(util.calls[-2:],[("release",3),("dispose",)])

    def test_32_empty_reads_are_bounded(self):
        device,util,result,log=self.run_capture([b""]*100)
        self.assertEqual(len(device.calls),32)
        self.assertEqual(result["read_calls"],32)

    def test_malformed_data_never_raw_and_stops(self):
        _,_,result,log=self.run_capture([b"X"*20+SECRET])
        self.assertTrue(result["decode_failed"])
        self.assertEqual(result["read_calls"],1)
        self.assertNotIn(SECRET.hex(),log)

    def test_plan_and_existing_output_never_import_usb(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(c.main([]),0)
        self.assertIn("PLAN_ONLY",out.getvalue())
        with tempfile.TemporaryDirectory() as tmp,self.assertRaises(FileExistsError):
            c.main(["--approved-phone-queued-media-capture","--output",tmp])

if __name__=="__main__":unittest.main()
