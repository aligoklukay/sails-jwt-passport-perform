/**
 * AuthController
 *
 * @description :: Server-side actions for handling incoming requests.
 * @help        :: See https://sailsjs.com/docs/concepts/actions
 */

var passport = require('passport');
var { userSchema } = require("../validations/user");

function _onPassportAuth(req, res, error, user, info) {
  if (error) return res.json(error);
  if (!user) return res.unauthorized(null, info && info.code, info && info.message);

  return res.ok({
    token: CipherService.createToken(user),
    user: user
  });
}

module.exports = {


  /**
   * `AuthController.signup()`
   */
  signup: async function (req, res) {
    try {
      var values = req.allParams();

      //Validate email and password
      userSchema
        .isValid(values)
        .then(async function () {
          let user = await User.create({
            email: values.email,
            password: values.password,
          }).fetch();

          return res.json({
            user,
            token: CipherService.createToken(user),
          });
        })
        .catch(function (err) {
          if (err.code == "E_UNIQUE") {
            return res.json({
              status: false,
              message: `Hata!Bu email adresi sistemde kayıtlıdır.`,
            });
          } else {
            return res.json(err);
          }
        });
    } catch (error) {
      return res.serverError(error);
    }


  },

  /**
   * `AuthController.signin()`
   */
  signin: async function (req, res) {
    passport.authenticate('local',
    _onPassportAuth.bind(this, req, res))(req, res);
  }

};

