# 步骤
    提醒，以下链接访问，都需要科学上网

## 1. 注册 Google 账户
比如注册gmail， ai8rs@gmail.com 

若之前就有账号，可以跳过

## 2. 激活 Google Cloud 账户

[免费开始使用，目前激活送$300，平台内可用](https://console.cloud.google.com/freetrial?hl=zh-cn)

需要添加您的信用卡信息(也可以使用公开可用的)，如招行Visa双币卡，地区选择香港(暂不支持中国大陆地区)

地址可以使用：香港湾仔区永祥街299号 邮编999077 电话00852-9169035

## 3. 激活 Resource Manager API
[https://cloud.google.com/iam/docs/granting-changing-revoking-access#gcloud](https://cloud.google.com/iam/docs/granting-changing-revoking-access?hl=zh-cn#gcloud)

## 4. 登录到 Google Cloud 控制台
[https://console.cloud.google.com/welcome/](https://console.cloud.google.com/welcome/)

默认名称为 “My First Project”, 也可以修改名称，如acme-ssl

记住对应ID，如 august-storm-888888-m1 

[进入IAM管理界面，选择项目，并全授权](https://console.cloud.google.com/projectselector2/iam-admin/iam?supportedpurview=project,folder,organizationId&_ga=2.244936837.1215512018.1720492014-1832715961.1719985241)

## 5. 安装 Google Cloud CLI
[完整的获取EAB，参考这篇](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial?hl=zh-cn)

[安装 Google Cloud CLI 链接](https://cloud.google.com/sdk/docs/install?hl=zh-cn)
```
## For Debian/Ubuntu
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg

echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list

sudo apt-get update && sudo apt-get install google-cloud-cli
```

## 6. 创建 EAB
```
gcloud init

gcloud config set project august-storm-888888-m1 

gcloud services enable publicca.googleapis.com

gcloud publicca external-account-keys create
```

以上，可能还有一些选项，如1/2/3之类的，按照提示执行即可。

运行后，可以看到如下：

```
Created an external account key
[b64MacKey: G2DqECDwQl9kbAc1KPOZVvZmklEptMyq******************************************************
keyId: 291aed91************************]
```