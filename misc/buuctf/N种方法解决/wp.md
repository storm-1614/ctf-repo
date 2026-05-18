# buuctf N种方法解决 wp

附件只有一个 exe 后缀的文件：
```
  Length      Date    Time    Name
---------  ---------- -----   ----
     3870  2015-10-30 10:52   KEY.exe
---------                     -------
     3870                     1 file

```

解压 wine 运行不了：
```
Application could not be started, or no application associated with
the specified file.
ShellExecuteEx failed: Bad format.
```

file 发现就是 ASCII 文件:
```
KEY.exe: ASCII text, with very long lines (3870), with no line terminators
```

vim 查看:
```
data:image/jpg;base64,iVBORw0KGgoAAAANSUhEUgAAAIUAAACFCAYAAAB12js8AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAArZSURBVHhe7ZKBitxIFgTv/3 (省略一大堆)
```

显然，文件用 base64 转换了，解码看看:  
去掉 `data:image/jpg;base64,` 后用 base64 命令输出到一个 jpg 文件。  

``` bash
 base64 --decode input.txt >> output.jpg
```
发现图片是一个二维码，用 zbarimg 识别二维码即可得到 flag。   
