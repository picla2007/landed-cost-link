Landed cost con lectura de links
Subí esta carpeta a un repo de GitHub (o corré `vercel --prod` dentro de la carpeta).
En Vercel → Settings → Environment Variables agregá `ANTHROPIC_API_KEY`.
Hacé un Redeploy.
Abrí la URL de Vercel, pegá un link de producto y tocá "Analizar".
Si una plataforma bloquea la lectura, la app avisa y podés cargar el precio a mano.
Plataformas que bloquean (Alibaba)
Sin configurar nada: la app te pide pegar el texto de la página y lo analiza igual.
Opcional: agregá `SCRAPINGBEE_API_KEY` en Vercel para que lea el link solo. Es un servicio pago y consume créditos.
