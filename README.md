# spotify-oggmp4-dl
Downloads Spotify Tracks/Albums/Playlists/Podcasts in MP4_128, MP4_256, OGG_VORBIS_320, OGG_VORBIS_160 and OGG_VORBIS_96 formats 

# Installation
+ Install the `requirements.txt` file
+ MP4_***: Add a [CDM](https://forum.videohelp.com/threads/408031-Dumping-Your-own-L3-CDM-with-Android-Studio) in the `cdm` directory and [mp4decrypt](https://www.bento4.com/downloads/) in the `mp4decrypt` directory
+ OGG_VORBIS_***: Place the [playplay](https://duckduckgo.com/?q=playplay+decryptor) binary inside the `playplay` directory
+ Enter your `sp_dc` Spotify Cookie when first starting the program

> [!IMPORTANT]  
> Premium account required

# Usage
```ruby
usage: Spotify Downloader [-h] --id ID [--quality {MP4_128,MP4_128_DUAL,MP4_256,MP4_256_DUAL,OGG_VORBIS_320,OGG_VORBIS_160,OGG_VORBIS_96}] [--output OUTPUT] [--debug]

options:
  -h, --help            show this help message and exit
  --id ID               Spotify URL/URI/ID
  --quality {MP4_128,MP4_128_DUAL,MP4_256,MP4_256_DUAL,OGG_VORBIS_320,OGG_VORBIS_160,OGG_VORBIS_96}
                        Quality level
  --output OUTPUT       Output path
  --debug               Print debug information
```
