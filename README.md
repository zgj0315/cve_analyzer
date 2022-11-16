# cve数据分析
## 工程目的
匹配cpe对应的cve列表  
输入一个cpe列表和cve文件，输出匹配到的cve列表

## 流程说明
- [x] 下载cve文件，地址：https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.zip
- [x] 根据part, vendor, product, version匹配命中的cve
