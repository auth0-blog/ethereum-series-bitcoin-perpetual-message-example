"use latest";

const webtask = require('webtask-tools');
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const Promise = require('bluebird');

const explorers = require('bitcore-explorers-bitcore-lib-0.13.19');
const bitcore = explorers.bitcore;

const messagePrefix = 'WTMSG: ';

const salt = bcrypt.genSaltSync();

function promisifyStorage(webtaskContext) {
    const context = { context: webtaskContext.storage };
    
    const promisifiedGet = 
      Promise.promisify(webtaskContext.storage.get, context);
    
    function getNullCheck() {
        return promisifiedGet().then(data => {
            return data ? data : {};
        });
    }
    
    return { 
        get: getNullCheck,
        set: Promise.promisify(webtaskContext.storage.set, context)
    };
}

function createAccount(userId, testnet_) {
    const net = testnet_ ? 'testnet' : 'livenet';
    return {
        username: userId.username,
        passwordHash: bcrypt.hashSync(userId.password, salt),
        privateKeyWIF: bitcore.PrivateKey.fromRandom(net).toWIF(),
        testnet: testnet_ ? true : false
    }
}

function wifToAddressStr(privateKeyWIF) {
    return bitcore.PrivateKey.fromWIF(privateKeyWIF)
                             .toAddress()
                             .toString();
}

function splitId(req, res, next) {
    if(!req.body.id) {
        res.sendStatus(400);
        return;
    }

    const split = req.body.id.split(':', 2);
    if(split.length !== 2) {
        res.sendStatus(400);
        return;    
    }
    req.userId = {
        username: split[0],
        password: split[1]
    };
    next();
}

function checkPassword(req, res, next) {
    // splitId should always be the previous middleware.
    if(!req.userId) {
        res.sendStatus(500);
    }

    const storage = promisifyStorage(req.webtaskContext);

    storage.get().then(accounts => {
        req.account = accounts[req.userId.username];
        if(!req.account || 
           !bcrypt.compareSync(req.userId.password, req.account.passwordHash)) {
            res.sendStatus(401);
            return;
        }

        next();
    }, error => {
        res.status(500).send(error);
        return;
    });
}

// Express
const app = express();

//app.use(webtaskSimulator());
app.use(bodyParser.json());

function addressHandler(req, res) {
    const storage = promisifyStorage(req.webtaskContext);

    storage.get().then(accounts => {
        const account = accounts[req.userId.username];
        if(!account) {
            res.sendStatus(401);
            return;
        }

        res.json({
            address: wifToAddressStr(account.privateKeyWIF)
        });
    }, error => {
        res.status(500).send(error);
    });
}

app.post('/new', splitId, (req, res) => {
    const storage = promisifyStorage(req.webtaskContext);

    storage.get().then(accounts => {
        if(!accounts[req.userId.username]) {
            accounts[req.userId.username] = createAccount(req.userId, 
                                                          req.body.testnet);
            storage.set(accounts).then(() => {
                addressHandler(req, res);
            }, error => {
                res.status(500).send(error);        
            });
        } else {
            addressHandler(req, res);
        }
    }, error => {
        res.status(500).send(error);
    });
});

app.post('/debugNew', splitId, (req, res) => {
    const storage = promisifyStorage(req.webtaskContext);

    storage.get().then(accounts => {
        accounts[req.userId.username] = createAccount(req.userId, 
                                                      req.body.testnet);
        accounts[req.userId.username].privateKeyWIF = req.body.privateKeyWIF;
        storage.set(accounts).then(() => {
            addressHandler(req, res);
        }, error => {
            res.status(500).send(error);        
        });
    }, error => {
        res.status(500).send(error);
    });
});

// No auth is required to query a user's address
app.post('/address', splitId, addressHandler);

app.post('/privateKey', splitId, checkPassword, (req, res) => {
    res.json({
        privateKeyWIF: req.account.privateKeyWIF
    });
});

app.post('/message',  splitId, checkPassword, (req, res) => {
    if(typeof req.body.fee !== 'number' ||
       !req.body.message || 
       (req.body.message.toString().length + messagePrefix.length) > 40) {
        res.sendStatus(400);
        return;
    }

    const insight = new explorers.Insight(req.account.testnet ? 
                                          'testnet' : 'livenet');

    const getUnspentUtxos = 
        Promise.promisify(insight.getUnspentUtxos, { context: insight });
    const broadcast = 
        Promise.promisify(insight.broadcast, { context: insight });
    
    const from = wifToAddressStr(req.account.privateKeyWIF); 
    
    getUnspentUtxos(from).then(utxos => {
        let inputTotal = 0;
        utxos.some(utxo => {
            inputTotal += parseInt(utxo.satoshis);
            return inputTotal >= req.body.fee;
        });
        if(inputTotal < req.body.fee) {
            res.status(402).send('Not enough balance in account for fee');
            return;
        }

        const dummyPrivateKey = new bitcore.PrivateKey();
        const dummyAddress = dummyPrivateKey.toAddress();

        const transaction = 
            bitcore.Transaction()
                   .from(utxos)
                   .to(dummyAddress, 0)
                   .fee(req.body.fee)
                   .change(from)
                   .addData(`${messagePrefix}${req.body.message}`)
                   .sign(req.account.privateKeyWIF);
        
        broadcast(transaction.uncheckedSerialize()).then(body => {
            if(req.webtaskContext.secrets.debug) {
                res.json({
                    status: 'Message sent!',
                    transactionId: body,
                    transaction: transaction.toString(),
                    dummyPrivateKeyWIF: dummyPrivateKey.toWIF() 
                });
            } else {
                res.json({
                    status: 'Message sent!',
                    transactionId: body
                });
            }
        }, error => {
            res.status(500).send(error.toString());
        });
    }, error => {
        res.status(500).send(error.toString());
    });
});

module.exports = webtask.fromExpress(app);
