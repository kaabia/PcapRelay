'''
_______________________________________________________________________________#

 File    : tst.py
 Author  : Badr Bacem KAABIA
 Version : 0.1
 Date    : 22 October 2023
 Brief   : test script
_______________________________________________________________________________

MIT License

Copyright (c) 2023 Badr Bacem KAABIA

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

_______________________________________________________________________________#
'''
from __future__ import absolute_import
from argparse import ArgumentParser
import os

parser = ArgumentParser()

parser.add_argument("-i",
                    "--interface",
                    help="network interface to forward to",
                    type=str,
                    default="lo")
parser.add_argument("-p",
                    "--pcap_path",
                    help="path of the pcap file to monitor",
                    type=str,
                    default=os.path.join(os.path.dirname(__file__), "pcap_files", "captured_traffic.pcap"))

a = parser.parse_args()
print(a.interface)
print(a.pcap_path)
