const User = require('../models/user');
const jwt = require('jsonwebtoken');
const expressJwt = require ('express-jwt');
const _ = require('lodash');
const {OAuth2Client} = require('google-auth-library');
const fetch = require('node-fetch');
// sendgrid
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);


// exports.signup = (req, res) => {
//   console.log('REQ BODY ON SIGNUP', req.body);
//   const {name, email, password} = req.body;
//
//   User.findOne({email}).exec((err, user) => {
//     if(user) {
//       return res.status(400).json({
//         error: 'Email is taken'
//       });
//     }
//   });
//
//   let newUser = new User({name, email, password})
//
//   newUser.save((err, success) => {
//     if(err) {
//       console.log('SIGNUP ERROR', err);
//       return res.status(400).json({
//         error: err
//       });
//     }
//     res.json({
//       message: 'Signup success! Please signin'
//     });
//   });
// };

// SIGN UP
exports.signup = (req, res) => {
  const {
    name,
    email,
    password
  } = req.body;
  User.findOne({
    email
  }).exec((err, user) => {
    if (user) {
      return res.status(400).json({
        error: 'Email is taken'
      });
    };

    const token = jwt.sign({
      name,
      email,
      password
    }, process.env.JWT_ACCOUNT_ACTIVATION, {
      expiresIn: '10m'
    })
    const emailData = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: `Account activation link`,
      html: `
          <h3>Please use the following link to activate your account</h3>
          <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
          <hr>
          <p>This email may contain sensitive information</p>
          <p>${process.env.CLIENT_URL}</p>
        `
    };

    sgMail
      .send(emailData)
      .then(sent => {
        // console.log('SIGNUP EMAIL SENT', sent);
        return res.json({
          message: `Email has been sent to ${email}. Follow the instructions to activate your account`
        });
      })
      .catch(err => {
        // console.log('SIGNUP EMAIL SENT ERROR', err);
        return res.json({
          message: err.message
        });
      });
  });
};

// ACCOUNT ACTIVATION
exports.accountActivation = (req, res) => {
  const {token} = req.body;
  if (token) {
    jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, function(err, decoded) {
      if (err) {
        console.log('JWT VERIFY IN ACCOUNT ACTIVATION ERROR', err)
        return res.status(401).json({
          error: 'Expired link. Signup again'
        });
      }
      const {name, email, password} = jwt.decode(token);

      const user = new User({ name, email, password});

      user.save((err, user) => {
        if (err) {
          console.log('SAVE USER IN ACCOUNT ACTIVATION ERROR', err);
          return res.status(401).json({
            error: 'Error saving user in database. Try singup again.'
          });
        }
        return res.json({
          message: 'Signup success. Please signin.'
        })

      });
    });
  } else {
    return res.json({
      message: 'Something went wrong. Try again.'
    });
  }

};

// SIGN IN
exports.signin = (req, res) => {
  const {email, password} = req.body;
  // check if user exists
  User.findOne({email}).exec((err, user) => {
    if(err || !user){
      return res.status(400).json({
        error: 'User with that email does not exist. Please signup.'
      });
    }
    // authenticate
    if(!user.authenticate(password)){
      return res.status(400).json({
        error: 'Email and password do not match'
      });
    }
    // generate a token and send to client
    const token = jwt.sign({_id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
    const {_id, name, email, role} = user;

    return res.json({
      token,
      user: {_id, name, email, role}
    });
  });
}

exports.requireSignin = expressJwt({
  secret: process.env.JWT_SECRET // req.user
});


exports.adminMiddleware = (req, res, next) => {
  User.findById({_id: req.user._id}).exec((err, user) => {
    if(err || !user){
      return res.status(400).json({
        error: 'User not found'
      });
    }
    if(user.role !== 'admin'){
      return res.status(400).json({
        error: 'Admin resource - Access Denied'
      });
    }

    req.profile = user;
    next();
  });
};

// ask for password link
exports.forgotPassword = (req, res) => {
  const {email} = req.body;
  User.findOne({email}, (err, user) => {
    if(err || !user) {
      return res.status(400).json({
        error: 'User with that email does not exist'
      });
    }

    const token = jwt.sign({_id: user._id, name: user.name}, process.env.JWT_RESET_PASSWORD, {
      expiresIn: '10m'
    })
    // email password reset link
    const emailData = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: `Password Reset link`,
      html: `
          <h3>Please use the following link to reset your password</h3>
          <p>${process.env.CLIENT_URL}/auth/password/reset/${token}</p>
          <hr>
          <p>This email may contain sensitive information</p>
          <p>${process.env.CLIENT_URL}</p>
        `
    };
    // save link in the database
    return user.updateOne({resetPasswordLink: token}, (err, success) => {
      if(err) {
        console.log('RESET PASSWORD LINK ERROR');
        return res.status(400).json({
          error: 'Database connection error on user password forgot request'
        });
      } else {
        // send email password reset link
        sgMail
          .send(emailData)
          .then(sent => {
            // console.log('SIGNUP EMAIL SENT', sent);
            return res.json({
              message: `Email has been sent to ${email}. Follow the instructions to reset your password`
            });
          })
          .catch(err => {
            // console.log('SIGNUP EMAIL SENT ERROR', err);
            return res.json({
              message: err.message
            });
          });
      }
    });
  });
};
// take link and new password
exports.resetPassword = (req, res) => {
  const {resetPasswordLink, newPassword} = req.body;
  // verify
  if(resetPasswordLink){
    jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function(err, decoded){
      if(err){
        return res.status(400).json({
          error: 'Expired link - Try again'
        });
      }
      // find user based on the link
      User.findOne({resetPasswordLink}, (err, user) => {
        if(err || !user) {
          return res.status(400).json({
            error: 'Something went wrong - Try later'
          });
        }
        // update the fields
        const updatedFields = {
          password: newPassword,
          resetPasswordLink: ''
        }
        // extend to that existing user the updated information
        user = _.extend(user, updatedFields);
        user.save((err, result) => {
          if(err){
            return res.status(400).json({
              error: 'Error resetting user password'
            });
          }
          res.json({
            message: `Great! Now you can login with your new password.`
          })
        })

      })
    })
  }
};
// new client using package
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
exports.googleLogin = (req, res) => {
  // get token from request body coming in from react
  const {idToken} = req.body;
  // use client to verify ID token
  client.verifyIdToken({idToken, audience: process.env.GOOGLE_CLIENT_ID}).then(response => {
    // console.log('GOOGLE SIGN IN RESPONSE', response)
    // grab email verified (true or false)
    // destructure needed info for sign in from response
    const {email_verified, name, email} = response.payload;
    if(email_verified) {
      // check if user exists all ready
      User.findOne({email}).exec((err, user) => {
        if(user) {
          // generate token if we find the user
          const token = jwt.sign({_id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
          // send token and user info to client
          const {_id, email, name, role} = user;
          return res.json({
            token, user: {_id, email, name, role}
          });
        // if user doesn't exist
        } else {
            let password = email;
            user = new User({name, email, password});
            // data (all ready used user variable)
            user.save((err, data) => {
              if(err) {
                console.log('ERROR GOOGLE SIGN IN ON USER SAVE', err);
                return res.status(400).json({
                  error: 'User sign in failed with Google'
                });
              }
              // generate token based on user id (data variable see above)
              const token = jwt.sign({_id: data._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
              // send token and user info to client
              const {_id, email, name, role} = data;
              return res.json({
                token, user: {_id, email, name, role}
              });
            });
        }
      });
    } else {
      return res.status(400).json({
        error: 'Google sign in failed - Try again'
      });
    }
  });
};


exports.facebookLogin = (req, res) => {
  console.log('FACEBOOK LOGIN REQ BODY', req.body);
  const {userID, accessToken} = req.body;
  const url = `https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}`

  return(
    fetch(url, {
      method: 'GET'
    })
    .then(response => response.json())
    .then(response => {
      const {email, name} = response;
      User.findOne({email}).exec((err, user) => {
        if(user) {
          // generate token if we find the user
          const token = jwt.sign({_id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
          // send token and user info to client
          const {_id, email, name, role} = user;
          return res.json({
            token, user: {_id, email, name, role}
          });
        } else {
          let password = email;
          user = new User({name, email, password});
          // data (all ready used user variable)
          user.save((err, data) => {
            if(err) {
              console.log('ERROR FACEBOOK SIGN IN ON USER SAVE', err);
              return res.status(400).json({
                error: 'User sign in failed with Facebook'
              });
            }
            // generate token based on user id (data variable see above)
            const token = jwt.sign({_id: data._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
            // send token and user info to client
            const {_id, email, name, role} = data;
            return res.json({
              token, user: {_id, email, name, role}
            });
          });
        }
      });
    })
    .catch(error => {
      res.json({
        error: 'Facebook login failed - Try again.'
      });
    })
  );
};
