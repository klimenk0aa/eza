# eza
Extnded Zabbix API
==================

Несколько методов, облегяабщих получение информации из Zabbix. Например, какие алерты получает пользователь.  


Использование:  
virtualenv eza  
source eza/bin/activate  
pip install -r requirements.txt  
uvicorn main:app --reload  
python3 admin_add.py  

http://127.0.0.1:8000/docs
