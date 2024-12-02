# 🔒 Sing-box V2ray 节点收集 🌐

### GitHub节点收集分类

* 收集的所有节点在All_Subs.txt
* 分类节点在Splitted-By-Protocol文件夹下
* 如需订阅自行使用GitHub加速

### 本地使用方法
* git到本地
* 需要安装python
* 安装依赖   pip install -r requirements
* 运行 main.py
* 本地使用需注意main函数中列表的订阅链接做GitHub加速，否则网络不通，无法获取订阅内容

### Actions使用方法
* fork到自己的仓库
* 运行Actions，获得Splitted-By-Protocol订阅内容
* .github文件中的工作流run_main_fetch.yml定时未开，更改【  #   - cron: "0 */4 * * *" 】# 注释掉定时触发，去掉注释触发每4小时执行收集节点一次
* Actions运行报错，确保 GITHUB_TOKEN 有足够权限

  参考步骤：
  打开你的 GitHub 仓库。
  进入 Settings > Actions > General。
  滑动到 Workflow permissions，确保选择的是：Read and write permissions。
启用 Allow GitHub Actions to create and approve pull requests（如果适用）。
保存设置。


### 说明
* 项目fork前辈，适当修改，仅供Python学习交流使用
* 节点获取地址更改和定阅，github搜索节点，只支持类似["vmess://", "vless://", "trojan://", "ss://", "ssr://", "hy2://", "tuic://", "warp://"]形式
* 打开main.py，在函数main中，找到列表links（base64编码）和dir_links，将找到的类似订阅地址，放入对应的这两个列表内，订阅地址内容要注意！！！
* 运行main.py,在subs文件中生成分类的节点类型，订阅或复制使用



#
![Visitor's Count](https://profile-counter.glitch.me/Supprise0901_fetchNodes/count.svg)
