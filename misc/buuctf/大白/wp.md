# buuctf 大白 wp

提供了一张图片，打不开。（似乎可以在 windows 上用自带图片查看器打开，可是我是 Linux……)  
使用 [pngcheck](https://github.com/pnggroup/pngcheck) 查看图片错误：  
```
❯ pngcheck -v dabai.png
zlib warning:  different version (expected 1.2.11, using 1.3.2)

File: dabai.png (150560 bytes)
  chunk IHDR at offset 0x0000c, length 13
    679 x 256 image, 32-bit RGB+alpha, non-interlaced
  CRC error in chunk IHDR (computed 8e14dfcf, expected 6d7c7135)
ERRORS DETECTED in dabai.png
```

发现是 CRC 错误

忽略 CRC 错误，用 display 查看图片。  
```
display -define png:ignore-crc=true dabai.png
```
发现是半张大白。  
用 [AabyssZG/Deformed-Image-Restorer](https://github.com/AabyssZG/Deformed-Image-Restorer) 轮子一键修复即可得到图片。  


