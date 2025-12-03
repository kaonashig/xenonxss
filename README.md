# XenonXSS
Varredor de XSS sem enrolação.

Instalação rápida:


git clone 
cd XenonXSS
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 xenonxss.py -u http://target.com.br


Flag interessantes:

- --single URL         teste de um único endpoint  
- --depth 3            aprofunda 3 níveis ao rastrear  
- --custom PAYLOAD     usa um payload seu  
- --proxy '{"http":"http://127.0.0.1:8080"}'   Burp na mão  

Resultados são gravados em `output/*.json`
