with open('database/models.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
text = text.replace("datetime('now')", "NOW()")
text = text.replace('INTEGER DEFAULT 1', 'SMALLINT DEFAULT 1')
text = text.replace('INTEGER DEFAULT 0', 'SMALLINT DEFAULT 0')

with open('database/models_pg.py', 'w', encoding='utf-8') as f:
    f.write(text)
print('Wrote models_pg.py')
