/**
 * User Yup Schema
 */

const yup = require('yup');

exports.userSchema = yup.object().shape({
  email: yup.string().required().email(),
  password: yup.string().required(),
});
