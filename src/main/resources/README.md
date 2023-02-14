# 鍵生成

## 秘密鍵の作成
openssl genrsa -out private.pem 2048

## Java向けにDER形式に変更
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.der -nocrypt

## 公開鍵を作成
openssl rsa -in private.pem -pubout -outform DER -out public.der
