# My documents service

## Running
```bash
pip install -r requirements.txt
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
python app.py
```

## Exploit:

- Register user
- Login
- Do search with some [payload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2)
