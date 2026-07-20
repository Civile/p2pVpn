// Configurazione pm2 per il control plane (p2p-holepunch).
//
// Due sezioni:
//   - `apps`   : come pm2 esegue il processo (il binario Rust gia' compilato).
//   - `deploy` : come pm2 tira il codice dal repo GitHub sul droplet.
//
// -----------------------------------------------------------------------------
// SETUP INIZIALE (una volta sola, dalla tua macchina locale):
//
//   1. Sostituisci IP_DEL_DROPLET qui sotto con l'IP reale del server.
//   2. Assicurati che il droplet abbia la chiave SSH e possa clonare da GitHub.
//   3. Predisponi la struttura di deploy sul server:
//        pm2 deploy deploy/ecosystem.config.js production setup
//   4. Primo deploy:
//        pm2 deploy deploy/ecosystem.config.js production
//
// DEPLOY SUCCESSIVI (dopo un git push su main):
//        pm2 deploy deploy/ecosystem.config.js production
//
// pm2 deploy crea questa struttura sotto /var/www/vpn:
//   /var/www/vpn/source    -> checkout del repo
//   /var/www/vpn/current   -> symlink alla release attiva (da qui gira l'app)
//   /var/www/vpn/shared    -> file persistenti tra i deploy (es. il database)
// -----------------------------------------------------------------------------

module.exports = {
  apps: [
    {
      name: 'vpn-control-plane',
      // Con pm2 deploy l'app gira dalla release corrente (symlink `current`).
      cwd: '/var/www/vpn/current',
      script: '/var/www/vpn/current/target/release/server',
      args: [],
      instances: 1,
      exec_mode: 'fork', // il server bind-a porte fisse: NON usare cluster.
      autorestart: true,
      max_restarts: 10,
      max_memory_restart: '300M',
      env: {
        // Porta interna del backoffice HTTP dietro nginx.
        HTTP_PORT: '8124',
        // URL pubblico usato dall'app per costruire i link (device-code, ecc.).
        PUBLIC_URL: 'https://abc.edoardocasella.it',
        // DB in `shared/`: sopravvive ai deploy (non viene sovrascritto dal checkout).
        DB_PATH: '/var/www/vpn/shared/data.db',
      },
      out_file: '/var/log/vpn/control-plane.out.log',
      error_file: '/var/log/vpn/control-plane.err.log',
      merge_logs: true,
      time: true,
    },
  ],

  deploy: {
    production: {
      user: 'root',
      // TODO: sostituisci con l'IP del droplet (o abc.edoardocasella.it dopo il DNS).
      host: 'IP_DEL_DROPLET',
      ref: 'origin/main',
      repo: 'https://github.com/Civile/p2pVpn.git',
      path: '/var/www/vpn',

      // Eseguito UNA VOLTA con `... production setup`: crea /var/log/vpn e shared/.
      'pre-setup': 'mkdir -p /var/log/vpn',

      // Eseguito sul server dopo ogni pull: build del binario e reload pm2.
      // `--update-env` ricarica anche le variabili d'ambiente definite sopra.
      'post-deploy': [
        'cargo build --release --bin server',
        'pm2 startOrReload deploy/ecosystem.config.js --update-env',
        'pm2 save',
      ].join(' && '),
    },
  },
};
