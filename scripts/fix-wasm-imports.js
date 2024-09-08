const fs = require('fs');
const path = './wasm/prover/pkg/snippets/wasm-bindgen-rayon-3e04391371ad0a8e/src/workerHelpers.worker.js';

fs.readFile(path, 'utf8', (err, data) => {
    if (err) throw err;
    const result = data.replace("import initWbg, { wbg_rayon_start_worker } from '../../../';",
        "import initWbg, { wbg_rayon_start_worker } from '../../../tlsn_extension_rs.js';");

    fs.writeFile(path, result, 'utf8', (err) => {
        if (err) throw err;
        console.log('File has been updated');
    });
});