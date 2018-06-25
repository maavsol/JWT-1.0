const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const fs = require('fs');

const User = require("../models/User");

router.post("/signup", (req, res, next) => {
  User.find({ email: req.body.email })
    .exec()
    .then(user => {
      if (user.length >= 1) {
        return res.status(409).json({
          message: "Mail exists"
        });
      } else {
        bcrypt.hash(req.body.password, 10, (err, hash) => {
          if (err) {
            return res.status(500).json({
              error: err
            });
          } else {
            const user = new User({
              _id: new mongoose.Types.ObjectId(),
              email: req.body.email,
              password: hash
            });
            user
              .save()
              .then(result => {
                console.log(result);
                res.status(201).json({
                  message: "user created"
                });
              })
              .catch(err => {
                console.log(err);
                res.status(500).json({
                  error: err
                });
              });
          }
        });
      }
    });
});

router.post("/login", (req, res, next) => {
var secretKey = fs.readFileSync('clave-privada.pem', 'utf8')
var publicKey = fs.readFileSync('clave-publica.pem', 'utf8')
console.log(secretKey)
console.log(publicKey)

  User.find({ email: req.body.email })
    .exec()
    .then(user => {
        if (user.length < 1) {
            return res.status(401).json({
                message: 'auth failed',
            })
        } 
        bcrypt.compare(req.body.password, user[0].password, (err, result) => {
            if (err) {
                return res.status(401).json({
                    message: 'auth failed',
                })
            }
            if(result){
                const token = jwt.sign({
                    email: user[0].email,
                },  secretKey, 
                {
                    audience: 'https://oauth2.zonadeprueba.es/token',  
                    issuer: 'iss-momopocket-44',
                    subject: 'sub-cupros',
                    jwtid: JSON.stringify(Math.random()*123456),
                    expiresIn: 60 * 60,
                    algorithm: "RS256",
                    
                })
                return res.status(200).json({
                    message: 'auth successful',
                    token: token,
                })
            }
            return res.status(401).json({
                message: 'auth failed',
            })
        })
    })
    .catch(err => {
        console.log(err);
        res.status(500).json({
          error: err
        });
      });
});

router.delete("/:userId", (req, res, next) => {
  User.remove({ _id: req.params.userId })
    .exec()
    .then(result => {
      res.status(200).json({
        message: "user deleted"
      });
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        error: err
      });
    });
});

module.exports = router;
