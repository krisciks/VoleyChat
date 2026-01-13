//piesledz express
const express = require('express');
const path = require('path');
//sesijas lai serveris atceras, kurs lietotajs ir ielogojies.
const session = require('express-session');
//parolu sifresanai
const bcrypt = require('bcrypt');
//pieslegums datubāzei
const db = require('./db');

//izveido express aplikaciju
const app = express();
//nosaka portu
const PORT = process.env.PORT || 3000;

//atlaauj sanemt json datus
app.use(express.json());
//atlaauj sanemt datus
app.use(express.urlencoded({ extended: true }));


//saglaba lietotaja sesiju 24 stundas
app.use(session({
  secret: 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

//laauj ieladet html css un js failus
app.use(express.static(path.join(__dirname)));


//atgriez datus no datubazes pec id
function getUserById(id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT id, name, surname, email, created_at FROM users WHERE id = ?', [id], (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}


//izveido jaunu lietotaju
app.post('/api/register', async (req, res) => {
  try {
    //parbauda datus
    const { name, surname, email, password } = req.body;
    if (!name || !surname || !email || !password) return res.status(400).json({ error: 'Kļūda' });

    //parbauda epastu
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) return res.status(500).json({ error: 'Datubāzes kļūda' });
      if (row) return res.status(400).json({ error: 'Epasts jau izmantots' });

      //hasho paroli
      const hash = await bcrypt.hash(password, 10);

      //saglaba datubaze un ielogojas
      db.run('INSERT INTO users (name, surname, email, password_hash) VALUES (?, ?, ?, ?)', [name, surname, email, hash], function(err) {
        if (err) return res.status(500).json({ error: 'Neizdevās izveidot kontu' });
        req.session.userId = this.lastID;
        getUserById(this.lastID).then(user => res.json({ user })).catch(e => res.status(500).json({ error: 'konts neatrasts' }));
      });
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Servera kļūda' });
  }
});

//login sistema
app.post('/api/login', (req, res) => {
  //panem epastu un paroli
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Nav epasts vai parole' });

  //mekle lietotaju datubaze pec epasta
  db.get('SELECT id, name, surname, email, password_hash FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: 'Datubāzes kļūda' });
    if (!row) return res.status(400).json({ error: 'Nepareizi ievadīta informācija' });

    //parbauda vai parole ir pareiza
    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) return res.status(400).json({ error: 'Nepareiza parole' });

    //saglaba sesiju un aizsuta datus
    req.session.userId = row.id;
    res.json({ user: { id: row.id, name: row.name, surname: row.surname, email: row.email } });
  });
});

app.post('/api/logout', (req, res) => {
  //izdzes sesiju
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', async (req, res) => {
  //ja nav sesija nav ielogojies
  if (!req.session.userId) return res.json({ user: null });
  try {
    //iegust datus no datubazes
    const user = await getUserById(req.session.userId);
    res.json({ user });
  } catch (e) {
    res.status(500).json({ error: 'Nav atrasts konts' });
  }
});


app.get('/api/posts', (req, res) => {
  //iegust ierakstus sakartotus pec datuma
  const sql = `SELECT posts.id, posts.content, posts.created_at, users.id as user_id, users.name, users.surname
               FROM posts JOIN users ON posts.user_id = users.id
               ORDER BY posts.created_at DESC`;
  //izpilda sql
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Datubāzes kļūda' });
    //nosuta ierakstus
    res.json({ posts: rows });
  });
});

app.post('/api/posts', (req, res) => {
  //parbauda vai ir ielogojies
  if (!req.session.userId) return res.status(401).json({ error: 'Nav apstiprināts lietotājs' });
  const { content } = req.body;
  //nelauj tuksu ierakstu saglabat
  if (!content || !content.trim()) return res.status(400).json({ error: 'Tukšs' });

  //pievieno ierakstu datubaze ar id
  db.run('INSERT INTO posts (user_id, content) VALUES (?, ?)', [req.session.userId, content.trim()], function(err) {
    if (err) return res.status(500).json({ error: 'Datubāzes kļūda' });
    //dabu ieraksta id
    const postId = this.lastID;
    //visus datus ar posta owner iegust
    db.get('SELECT posts.id, posts.content, posts.created_at, users.id as user_id, users.name, users.surname FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = ?', [postId], (err, row) => {
      if (err) return res.status(500).json({ error: 'Neizdevās atrast datubāzi' });
      //gatavs ieraksts nosutits
      res.json({ post: row });
    });
  });
});


app.delete('/api/posts/:id', (req, res) => {
  //parbauda vai ir ielogojies
  if (!req.session.userId) return res.status(401).json({ error: 'Nav apstiprināts lietotājs' });
  //ieraksta id
  const postId = req.params.id;
  //parbauda kura ieraksts tas ir
  db.get('SELECT user_id FROM posts WHERE id = ?', [postId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Datubāzes kļūda' });
    if (!row) return res.status(404).json({ error: 'Ieraksts netika atrasts' });
    //ja nepieder tev ieraksts
    if (row.user_id !== req.session.userId) return res.status(403).json({ error: 'Not allowed' });

    //ieraksta izdzesana
    db.run('DELETE FROM posts WHERE id = ?', [postId], function(err) {
      if (err) return res.status(500).json({ error: 'Dzēšanas kļūda' });
      res.json({ ok: true });
    });
  });
});

//pasaka serverim un izvada terminali kura porta viss iet
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
