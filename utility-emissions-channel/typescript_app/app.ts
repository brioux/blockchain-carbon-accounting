import { config } from 'dotenv';
import express, { Express, json, urlencoded, RequestHandler } from 'express';
// import LedgerIntegration from './src/blockchain-gateway/ledger-integration';
import { serve, setup } from 'swagger-ui-express';
import swaggerDocsV2 from './swagger.v2-ws.json';
// import swaggerDocs from './swagger.json';
import multer from 'multer';
import { LedgerIntegrationV2 } from './src/blockchain-gateway/ledger-integration-v2';

const env = process.env.NODE_ENV;
if (env) {
    const cfgOut = config({ path: `.env.${env}` });
    if (cfgOut.error) {
        console.error(cfgOut.error);
        process.exit(1);
    }
    console.log(`using ${env} ethereum network`);
} else {
    config();
}

const app: Express = express();
const upload = multer();
const PORT = process.env.PORT || 9000;

app.use(json() as RequestHandler);
app.use(urlencoded({ extended: true }));
app.use(upload.single('emissionsDoc'));

app.use('/v2-api-docs', serve, setup(swaggerDocsV2));
// const ledgerIntegration = new LedgerIntegration(app);
// swagger Document
// app.use('/api-docs', serve, setup(swaggerDocs));
// ledgerIntegration
// .build()
// .then(() => {

new LedgerIntegrationV2(app);

const server = app.listen(PORT, () => {
    console.log(`++++++++++++++++ Hyperledger CA2 SIG /// Carbon Accouncting API ++++++++++++++++`);
    console.log(`++ REST API PORT : ${PORT}`);
    console.log(`++ ACCESS SWAGGER : http://localhost:${PORT}/api-docs/`);
    console.log(`++ ACCESS SWAGGER V2 : http://localhost:${PORT}/v2-api-docs/`);
    console.log(`++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++`);
});




// })
// .catch((error) => {
// console.error('failed to build ledger Integration : %o', error);
// });
