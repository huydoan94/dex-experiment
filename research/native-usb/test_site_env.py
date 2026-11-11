import os
import unittest
from unittest.mock import patch

import site_env


class SiteEnvTests(unittest.TestCase):
    def tearDown(self):
        site_env._selected = None

    def test_defaults_keep_the_earlier_profile_with_a_generic_name(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(site_env.sink_name(), "DeX-PC")
            self.assertEqual(site_env.video_mode(), "1080p30")
            self.assertEqual(site_env.video_formats(),
                             "38 00 02 04 00000081 00000000 00000000 00 0000 0000 00 none none")
            self.assertEqual(site_env.to_desktop(1919, 1079), (1919, 1079))

    def test_all_offers_the_official_list(self):
        with patch.dict(os.environ, {"DEX_VIDEO_MODE": "all"}, clear=True):
            self.assertEqual(site_env.video_formats(),
                             "02 00 02 04 0001DEFF 157C7FFF 00000FFF 00 0000 0000 00 none none")
            self.assertEqual(site_env.picked(0x40, 0, 0), ("CEA", 1280, 720, 60))
            self.assertEqual(site_env.picked(0, 1 << 28, 0), ("VESA", 1920, 1200, 30))
            self.assertIsNone(site_env.picked(0, 1 << 29, 0))      # 1920x1200p60 is not offered
            self.assertEqual(site_env.picked(0, 0, 1 << 9), ("HH", 960, 540, 60))
            self.assertIsNone(site_env.picked(0x100, 0, 0))      # 1080p60 is not offered
            self.assertIsNone(site_env.picked(0x40, 1, 0))       # two tables
            self.assertIsNone(site_env.picked(0x41, 0, 0))       # two entries
            self.assertIsNone(site_env.picked(0, 0, 0))

    def test_1080p60_offers_both_1080_rates(self):
        with patch.dict(os.environ, {"DEX_VIDEO_MODE": "1080p60"}, clear=True):
            self.assertEqual(site_env.video_formats(),
                             "40 00 02 04 00000181 00000000 00000000 00 0000 0000 00 none none")
            self.assertEqual(site_env.picked(0x100, 0, 0), ("CEA", 1920, 1080, 60))
            self.assertEqual(site_env.picked(0x80, 0, 0), ("CEA", 1920, 1080, 30))
            self.assertIsNone(site_env.picked(0x40, 0, 0))

    def test_60fps_offers_only_60_fps_entries(self):
        with patch.dict(os.environ, {"DEX_VIDEO_MODE": "60fps"}, clear=True):
            self.assertEqual(site_env.video_formats(),
                             "A9 00 02 04 00000041 00282AAA 00000000 00 0000 0000 00 none none")
            offered = [site_env.VESA[b] for b in range(30) if 0x00282AAA >> b & 1]
            self.assertTrue(all(f == 60 for _, _, f in offered))
            self.assertEqual([(w, h) for w, h, _ in offered][-2:], [(1440, 900), (1600, 900)])
            self.assertEqual(site_env.picked(0, 1 << 21, 0), ("VESA", 1600, 900, 60))
            self.assertEqual(site_env.picked(0x40, 0, 0), ("CEA", 1280, 720, 60))
            self.assertIsNone(site_env.picked(0x80, 0, 0))
            self.assertIsNone(site_env.picked(0, 1 << 20, 0))   # 1600x900p30 not offered

    def test_default_mode_accepts_only_its_two_entries(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(site_env.picked(0x80, 0, 0), ("CEA", 1920, 1080, 30))
            self.assertEqual(site_env.picked(0x01, 0, 0), ("CEA", 640, 480, 60))
            self.assertIsNone(site_env.picked(0x40, 0, 0))

    def test_input_follows_the_phones_pick(self):
        site_env.select(1280, 720)
        self.assertEqual(site_env.to_desktop(0, 0), (0, 0))
        self.assertEqual(site_env.to_desktop(960, 540), (640, 360))
        self.assertEqual(site_env.to_desktop(1919, 1079), (1279, 719))
        site_env.select(640, 480)
        self.assertEqual(site_env.to_desktop(1919, 1079), (639, 479))

    def test_invalid_values_fall_back(self):
        for name in ("", "has space", "x" * 33, "a/&%b", "ünï"):
            with patch.dict(os.environ, {"DEX_SINK_NAME": name}, clear=True):
                self.assertEqual(site_env.sink_name(), "DeX-PC")
        for mode in ("2160p60", "720p60"):
            with patch.dict(os.environ, {"DEX_VIDEO_MODE": mode}, clear=True):
                self.assertEqual(site_env.video_mode(), "1080p30")


if __name__ == "__main__":
    unittest.main()
