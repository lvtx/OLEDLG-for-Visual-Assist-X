# OLEDLG for Visual Assist X

#### 软件作者
软件作者：lvtx

#### 软件介绍
ASM OLEDLG for Visual Assist X 通用破解补丁

#### 使用说明

1. 本补丁程序是使用 RadASM 3.x 纯汇编编写和编译出来的，原理是利用 OLEDLG.dll API 劫持 VA_X.dll 来实现替换 Visual Assist X 的注册 Public Key，从而可以使用 DoubleLabyrinth 老大以前发布过的 [VisualAssist-keygen-demo](https://github.com/DoubleLabyrinth/VisualAssist-keygen-demo.git) 来算出属于自己的注册码。
 ![输入图片说明](https://images.gitee.com/uploads/images/2021/0726/223855_980d0a61_1232593.png "001.png")
 ![输入图片说明](https://images.gitee.com/uploads/images/2021/0726/223905_bbff7222_1232593.png "002.png")
 ![输入图片说明](https://images.gitee.com/uploads/images/2021/0726/223913_3f9f6ec8_1232593.png "003.png")

2. 使用本补丁程序需要注意的一点就是，OLEDLG.dll 需要复制到VS各个版本的主程序 devenv.exe 所在的同一目录内才会有效。
（注意是VisualStudio的 Devenv.exe所在目录, 不是VisualAssist所在目录。可以鼠标右键点击VS启动图标查看属性，可以查看目录位置）
 ![输入图片说明](https://images.gitee.com/uploads/images/2021/0726/223947_18e05cee_1232593.png "004.png")

3. 至于 KEYGEN 的使用方法，跟 DoubleLabyrinth 原版是完全一样的，本人只是稍微修改了一些地方而已，但不影响注册码的正常生成。如果想使用原版的话请自行到 DoubleLabyrinth 大佬的 Github 上去下载编译吧，在这里我就不帮忙上传了。
（注意是授权用户数量范围是：1 ~ 255，授权日期范围是：2000 ~ 2099[年份]）

```
   Usage:
       VisualAssist-keygen.exe <username> <license count> <expire date>

           [-renew]           Generate renew-key.
                              This parameter is optional.

           <username>         The username licensed to.
                              This parameter must be specified.

           <license count>    The maximum number of copies that can be run under the newly-generated license.
                              The value should be in 1 ~ 255.
                              This parameter must be specified.

           <expire date>      The date when the newly-generated license expires.
                              The format must be one of the following:
                                  1. "yyyy/mm/dd"
                                  2. "yyyy-mm-dd"
                                  3. "yyyy.mm.dd"
                              This parameter must be specified.
```
 ![输入图片说明](https://images.gitee.com/uploads/images/2021/0726/224106_97675254_1232593.png "005.png")
 ![输入图片说明](https://images.gitee.com/uploads/images/2021/0726/224121_fc2d26a2_1232593.png "006.png")
 ![输入图片说明](https://images.gitee.com/uploads/images/2021/0726/224135_0c684166_1232593.png "007.png")

#### 补充说明
注册完之后，升级、卸载或重新安装VAX时，会有key提示无效，点"Cancel"按钮即可。如果有新VS版本增加，需要点"No"按钮。
 ![输入图片说明](https://images.gitee.com/uploads/images/2021/0726/224145_5565f404_1232593.png "008.png")

#### 备注
最后说明一下，本补丁程序及源码仅供大家学习参考，请勿用作商业之上，否则后果自负。