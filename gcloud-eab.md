# Step
## 1. Register google account
For example, the gmail, such as: ai8rs@gmail.com

## 2. Active the Google Cloud Account

[Get started for free](https://console.cloud.google.com/freetrial)

Add your credit card infomation. Location HongKong.

Address: 香港湾仔区永祥街299号 Post Code: 999077 Phone: 00852-9169035

## 3. Enable the Resource Manager API
[https://cloud.google.com/iam/docs/granting-changing-revoking-access#gcloud](https://cloud.google.com/iam/docs/granting-changing-revoking-access#gcloud)

## 4. Login Google Cloud Console
[https://console.cloud.google.com/welcome/](https://console.cloud.google.com/welcome/)

Get your first project id, such as: august-storm-888888-m1 

[Go to the IAM page, and grant roles](https://console.cloud.google.com/projectselector2/iam-admin/iam?supportedpurview=project,folder,organizationId&_ga=2.244936837.1215512018.1720492014-1832715961.1719985241)

## 5. Install the Google Cloud CLI
[Request a certificate using Public CA](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial)

[Install the Google Cloud CLI](https://cloud.google.com/sdk/docs/install)
```
## For Debian/Ubuntu
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg

echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list

sudo apt-get update && sudo apt-get install google-cloud-cli
```

## 6. Create EAB
```
gcloud init

gcloud config set project august-storm-888888-m1 

gcloud services enable publicca.googleapis.com

gcloud publicca external-account-keys create
```

Then, you can see 

```
Created an external account key
[b64MacKey: G2DqECDwQl9kbAc1KPOZVvZmklEptMyq******************************************************
keyId: 291aed91************************]
```