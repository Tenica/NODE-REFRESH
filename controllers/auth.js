const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto')
const User = require('../models/user');
const { check, validationResult } = require('express-validator')

const transport = nodemailer.createTransport({
  host: "smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: "35c3bdb2095b56",
    pass: "2521ed2850f7eb"
  }
})




exports.getLogin = (req, res, next) => {
  let message = req.flash('error')
if (message.length > 0) {
    message = message[0];
} else {
  message = null
}
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    isAuthenticated: false,
    errorMessage: message,
    oldInput: {
      email: '',
      password: ''
    }, validationErrors: []
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error')
  if (message.length > 0) {
    message = message[0];
} else {
  message = null
}
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false,
    errorMessage: message,
    oldInput: { 
      email: '',
       password: '', 
       confirmPassword:''
    }, 
    validationErrors: []
  });
};


exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password
      },
      validationErrors: errors.array()
    });
  }

  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage: 'Invalid email or password.',
          oldInput: {
            email: email,
            password: password
          },
          validationErrors: []
        });
      }
      bcrypt
        .compare(password, user.password)
        .then(doMatch => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          }
          return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: 'Invalid email or password.',
            oldInput: {
              email: email,
              password: password
            },
            validationErrors: []
          });
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login');
        });
    })
    .catch(err => {
      const error = new Error(err)
      error.httpStatusCode = 500;
      return next(error)

  })
};


exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(errors.array());
    return res.status(422)
    .render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: { email: email,
         password: password, 
         confirmPassword: req.body.confirmPassword
        }, validationErrors: errors.array()
    })
  }
  User.findOne({ email: email })
    .then(userDoc => {
      if (userDoc) {
        req.flash('error', 'Email exists already!')
        return res.redirect('/signup');
      }
      return bcrypt
      .hash(password, 12)
      .then(hashedPassword => {
        const user = new User({
          email: email,
          password: hashedPassword,
          cart: { items: [] }
        });
        return user.save();
      })
      .then(result => {
        res.redirect('/login');
        return transport.sendMail({
          to: email,
          from: 'shop@checkout.com',
          subject: 'sign up succeeded',
          html: '<h1>You were successfully signed up</h1>'
        }, (error, info) => {
          if (error) {
            return console.log(error);
          }
          console.log('Message sent: %s', info.messageId);
        });
       
      })
    })
    .catch(err => {
      console.log(err);
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};


exports.getReset = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null
  }
  res.render('auth/reset', {
     path: '/reset',
     pageTitle: 'Reset Password',
     errorMessage:message
   })
}


exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect('/reset')
    }
    const token = buffer.toString('hex');
    User.findOne({email: req.body.email})
    .then(user => {
      if (!user) {
        req.flash('error', 'No account with that email found.')
        return res.redirect('/reset')
      }
      user.resetToken = token;
      user.resetTokenExpiration = Date.now() + 3600000
     return  user.save();
    }).then((result) => {
      res.redirect('/')
      return transport.sendMail({
        to: req.body.email,
        from: 'resetpassword.com',
        subject: 'Password reset',
        html: `<p>You requested a password reset</p>
        <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password</p>`
      }, (error, info) => {
        if (error) {
          return console.log(error);
        }
        console.log('Message sent: %s', info.messageId);
      });
      
    })
    .catch(err => {
console.log(err)
    });
  });
};


exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({resetToken: token, 
    resetTokenExpiration: {$gt: Date.now()}})
    .then(user => {
      let message = req.flash('error');
      if (message.length > 0) {
        message = message[0];
      } else {
        message = null
      }
       res.render('auth/new-password', {
         path: '/new-password',
         pageTitle: 'Get New Password',
         errorMessage: message ,
         userId: user._id.toString(),
         passwordToken: token
       })
    })
    .catch(err => {
      const error = new Error(err)
      error.httpStatusCode = 500;
      return next(error)

  })
 
}


exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId  =  req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    resetToken: passwordToken, 
    resetTokenExpiration: {$gt: Date.now()},
    _id: userId
  })
  .then(user => {
    resetUser = user
    return bcrypt.hash(newPassword, 12)
  }).then(hashedPassword => {
     resetUser.password = hashedPassword;
     resetUser.resetToken = undefined;
     resetUser.resetTokenExpiration = undefined;
     return resetUser.save();
  }).then((result) => {
     res.redirect('/login')
     
  })
  .catch(err => {
    const error = new Error(err)
    error.httpStatusCode = 500;
    return next(error)

})
}


