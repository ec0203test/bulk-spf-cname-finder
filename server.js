const express = require('express');
const dns = require('dns').promises;
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/lookup', async (req, res) => {
  const input = req.body.domains || '';
  const domains = input.split('\n').map(d => d.trim()).filter(Boolean);
  const results = {};

  for (let domain of domains) {
    results[domain] = { spf: null, cname: null };
    try {
      const txtRecords = await dns.resolveTxt(domain);
      const spf = txtRecords.flat().find(r => r.startsWith('v=spf1'));
      results[domain].spf = spf || 'No SPF found';
    } catch {
      results[domain].spf = 'Error or no TXT records';
    }

    try {
      const cname = await dns.resolveCname(domain);
      results[domain].cname = cname.join(', ');
    } catch {
      results[domain].cname = 'No CNAME found or not applicable';
    }
  }

  res.json(results);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

