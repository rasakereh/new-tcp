#!/bin/bash

insmod ../module/newTCPmod.ko
wget -O wave_ins.mp3 "https://www.sample-videos.com/audio/mp3/wave.mp3"
wget -O png_ins.png "https://www.sample-videos.com/img/Sample-png-image-10mb.png"
wget -O pdf_ins.pdf "https://www.sample-videos.com/pdf/Sample-pdf-5mb.pdf"
wget -O zip_ins.zip "https://www.sample-videos.com/zip/20mb.zip"
lsmod newTCPmod
wget -O wave_rm.mp3 "https://www.sample-videos.com/audio/mp3/wave.mp3"
wget -O png_rm.png "https://www.sample-videos.com/img/Sample-png-image-10mb.png"
wget -O pdf_rm.pdf "https://www.sample-videos.com/pdf/Sample-pdf-5mb.pdf"
wget -O zip_rm.zip "https://www.sample-videos.com/zip/20mb.zip"

