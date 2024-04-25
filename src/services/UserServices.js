const User = require("../models/UserModel");
const Code = require("../models/CodeModel");
const Piggy = require("../models/PiggyMode");
const dotenv = require("dotenv");
dotenv.config();
const bcrypt = require("bcrypt");
const { generalAccessToken } = require("./JwtService");
const crypto = require("crypto");
const EmailService = require("../services/EmailService");

const loginUser = (userLogin) => {
  return new Promise(async (resolve, reject) => {
    const { email, password } = userLogin;
    try {
      const checkUser = await User.findOne({ email: email });
      if (checkUser === null) {
        resolve({
          status: "ERR",
          message: "The user is not defined",
        });
      }
      const comparePassword = await bcrypt.compareSync(
        password,
        checkUser.password
      );
      if (!comparePassword) {
        resolve({
          status: "ERR",
          message: "The password is incorrect",
        });
      }

      const access_token = await generalAccessToken({
        id: checkUser._id,
        isAdmin: checkUser.isAdmin,
      });
      const data = {
        accessToken: access_token,
      };
      await User.findByIdAndUpdate(checkUser.id, data, { new: true });
      // const refresh_token = await generalRefreshToken({
      //     id: checkUser._id,
      //     isAdmin : checkUser.isAdmin
      // });
      const name = checkUser.name;
      const id = checkUser._id;

      resolve({
        status: "success",
        message: "Login successfully",
        id,
        name,
        access_token,
        //refresh_token
      });
      console.log("success login");
    } catch (error) {
      reject(error);
    }
  });
};

const resetPassword = (data) => {
  return new Promise(async (resolve, reject) => {
    const { email } = data;
    email = email.replace(/\s/g, "");
    try {
      const checkUser = await User.findOne({ email: email });
      if (checkUser === null) {
        return resolve({
          status: "ERR",
          message: "The user is not defined",
        });
      }

      const verificationCode = crypto
        .randomBytes(3)
        .toString("hex")
        .toUpperCase();

      const check = await Code.findOne({ email: email });
      if (check) {
        resolve({
          status: "error",
          message: "Please check your email box",
        });
      }

      const createCode = await Code.create({
        email,
        user: checkUser._id,
        code: verificationCode,
      });
      if (createCode) {
        resolve({
          status: "success",
          message: "Email sended",
        });
      }

      await EmailService.sendEmail(email, verificationCode);

      resolve({
        status: "success",
        message: "Email send successfully",
      });
    } catch (error) {
      reject(error);
    }
  });
};

const verifyCode = (data) => {
  return new Promise(async (resolve, reject) => {
    const { code } = data;
    code = code.replace(/\s/g, "");
    try {
      const checkCode = await Code.findOne({ code: code });
      if (checkCode === null) {
        return resolve({
          status: "error",
          message: "The code is wrong",
        });
      } else {
        resolve({
          status: "success",
          message: "Success verify code",
          data: checkCode.user,
        });
      }
    } catch (error) {
      reject(error);
    }
  });
};

const decodeToken = (data) => {
  return new Promise(async (resolve, reject) => {
    const { token } = data;
    try {
      const checkToken = await User.findOne({ accessToken: token });
      if (checkToken === null) {
        return resolve({
          status: "ERR",
          message: "Unauthorized",
        });
      } else {
        resolve({
          status: "OK",
          message: "Decode successfully",
        });
      }
    } catch (error) {
      reject(error);
    }
  });
};

const logoutUser = (data) => {
  return new Promise(async (resolve, reject) => {
    const { token } = data;
    try {
      const checkToken = await User.findOne({ accessToken: token });
      if (checkToken === null) {
        return resolve({
          status: "ERR",
          message: "Unauthorized",
        });
      }
      const data = {
        accessToken: null,
      };
      await User.findByIdAndUpdate(checkToken.id, data, { new: true });
      resolve({
        status: "success",
        message: "Decode successfully",
      });
    } catch (error) {
      reject(error);
    }
  });
};

const getImage = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkUser = await User.findOne({ _id: id });

      if (!checkUser) {
        return resolve({
          status: "error",
          message: "The user is not exist",
        });
      }
      const image = checkUser.image;
      resolve({
        image,
      });
    } catch (error) {
      console.error("Error updating user:", error);
      reject(error);
    }
  });
};
const updateUser = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkUser = await User.findOne({ _id: id });
      const checkEmail = await User.findOne({ email: data.email });

      if (checkEmail) {
        return resolve({
          status: "error",
          message: "Email already exists",
        });
      }

      if (!checkUser) {
        return resolve({
          status: "error",
          message: "The user is not exist",
        });
      }

      if (data.password && data.oldPassword) {
        if (data.password === data.oldPassword) {
          return reject({
            status: "error",
            message: "The new password must be different from the old password",
          });
        }

        const comparePassword = await bcrypt.compare(
          data.oldPassword,
          checkUser.password
        );

        if (!comparePassword) {
          return reject({
            status: "error",
            message: "The old password is incorrect",
          });
        }

        const hashPassword = await bcrypt.hash(data.password, 10);
        data.password = hashPassword;
      }

      const updatedUser = await User.findByIdAndUpdate(id, data, { new: true });
      resolve({
        status: "success",
        message: "User updated successfully",
        data: updatedUser,
      });
    } catch (error) {
      console.error("Error updating user:", error);
      reject(error);
    }
  });
};

const updatePass = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkUser = await User.findOne({ _id: id });
      if (!checkUser) {
        return resolve({
          status: "error",
          message: "The user is not exist",
        });
      }

      const comparePassword = await bcrypt.compare(
        data.password,
        checkUser.password
      );
      if (comparePassword) {
        return resolve({
          status: "error",
          message: "The new password must be different from the old password",
        });
      }
      const hashPassword = await bcrypt.hash(data.password, 10);
      data.password = hashPassword;

      const updatedUser = await User.findByIdAndUpdate(id, data, { new: true });
      const code = await Code.findOne({ user: id });
      if (code) {
        await Code.findByIdAndDelete(code._id);
      }
      if (updatedUser) {
        resolve({
          status: "success",
          message: "Update password successfully",
        });
      }
    } catch (error) {
      console.error("Error updating user:", error);
      reject(error);
    }
  });
};

const deleteUser = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkUser = await User.findOne({
        _id: id,
      });

      if (checkUser == null) {
        resolve({
          status: "error",
          message: "The user is not exist",
        });
      }

      await User.findByIdAndDelete(id);
      resolve({
        status: "success",
        message: "User delete successfully",
      });
    } catch (error) {
      reject(error);
    }
  });
};

const getAllUser = () => {
  return new Promise(async (resolve, reject) => {
    try {
      const allUser = await User.find();
      resolve({
        status: "success",
        message: "Get all user successfully",
        data: allUser,
      });
    } catch (error) {
      reject(error);
    }
  });
};

const getDetailsUser = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const user = await User.findOne({
        _id: id,
      });

      if (user == null) {
        return resolve({
          status: "error",
          message: "The user is not exist",
        });
      }

      resolve({
        status: "success",
        message: "Get detail user id:" + id + " successfully",
        data: user,
      });
    } catch (error) {
      reject(error);
    }
  });
};

const getDetailsUserWithCart = async (id) => {
  try {
    const userWithCarts = await User.findById(id).populate({
      path: "carts",
      populate: {
        path: "orderItems.product",
        model: "Product",
      },
    });

    if (!userWithCarts) {
      return {
        status: "error",
        message: "The user does not exist",
      };
    }

    return {
      status: "success",
      message: `Get detail user id: ${id} successfully`,
      data: userWithCarts.carts,
    };
  } catch (error) {
    return {
      status: "error",
      message: "An error occurred while fetching user details",
      error: error.message,
    };
  }
};

const deleteManyUser = (ids) => {
  return new Promise(async (resolve, reject) => {
    try {
      await User.deleteMany({ _id: ids });
      resolve({
        status: "success",
        message: "Delete user success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const sendMoney = async (data) => {
  try {
    const { userId, money } = data;
    console.log(userId);
    console.log(money);

    // Check user existence
    const checkUser = await User.findOne({ _id: userId });
    if (!checkUser) {
      return {
        status: "error",
        message: "The user does not exist",
      };
    }

    //const time = new Date();
    const time = new Date("2024-04-27T09:00:48.756Z");
    const checkPiggy = await Piggy.findOne({ user: userId });
    if (checkPiggy) {
      const timeMonth = time.getMonth();
      const timeDate = time.getDate();
      const updatedAtMonth = checkPiggy.updatedAt.getMonth();
      const updatedAtDate = checkPiggy.updatedAt.getDate();

      // Check if month and date components of time and updatedAt match
      if (timeMonth === updatedAtMonth && timeDate === updatedAtDate) {
        // Find entries in moneySend with the same month and date as updatedAt
        const moneySendEntry = checkPiggy.moneySend.find((entry) => {
          const entryMonth = entry.time.getMonth();
          const entryDate = entry.time.getDate();
          return entryMonth === updatedAtMonth && entryDate === updatedAtDate;
        });

        if (moneySendEntry) {
          // If entry found, update money and totalMoney
          moneySendEntry.money += money;
          checkPiggy.totalMoney += money;
          await checkPiggy.save();
        } else {
          // If no entry found, push a new entry to moneySend array
          checkPiggy.moneySend.push({ money: money, time: time });
          checkPiggy.totalMoney += money;
          await checkPiggy.save();
        }

        return {
          data: checkPiggy,
          status: "success",
          message: "Money updated successfully",
        };
      } else {
        const updatedPiggy = await Piggy.findByIdAndUpdate(
          checkPiggy._id,
          {
            $push: {
              moneySend: {
                money: money,
                time: time,
              },
            },
            $inc: {
              totalMoney: money,
            },
          },
          { new: true }
        );

        return {
          data: updatedPiggy,
          status: "success",
          message: "Money updated successfully",
        };
      }
    }

    // If no piggy record for today, create a new one
    const newPiggy = await Piggy.create({
      user: userId,
      moneySend: [{ money: money, time: time }],
      totalMoney: money,
    });

    return {
      data: newPiggy,
      status: "success",
      message: "Money sent successfully",
    };
  } catch (error) {
    console.error("Error:", error);
    throw error;
  }
};

const getTotalMoney = async (userId) => {
  try {
    const checkUser = await User.findOne({ _id: userId });
    if (!checkUser) {
      return {
        status: "error",
        message: "The user does not exist",
      };
    }

    const checkPiggy = await Piggy.findOne({ user: userId });
    if (!checkPiggy) {
      return {
        status: "error",
        message: "The piggy does not exist",
      };
    }

    const today = new Date();
    const currentMonth = today.getMonth() + 1; // Note: Tháng bắt đầu từ 0
    const currentYear = today.getFullYear();

    const moneyByDateMap = new Map();
    const moneyByDayOfWeekMap = new Map();

    checkPiggy.moneySend.forEach((entry) => {
      const entryMonth = entry.time.getMonth() + 1;
      const entryYear = entry.time.getFullYear();
      const day = entry.time.getDate();
      const dayOfWeek = entry.time.getDay();
      
      if (entryMonth === currentMonth && entryYear === currentYear) {
        const currentTotalByDate = moneyByDateMap.get(day) || 0;
        const currentTotalByDayOfWeek = moneyByDayOfWeekMap.get(dayOfWeek) || 0;
        moneyByDateMap.set(day, currentTotalByDate + entry.money);
        moneyByDayOfWeekMap.set(dayOfWeek, currentTotalByDayOfWeek + entry.money);
      }
    });

    const listMoneySendByMonth = [...moneyByDateMap.entries()];
    const listMoneySendByWeek = [...moneyByDayOfWeekMap.entries()];

    console.log("listMoneySendbyMonth:", listMoneySendByMonth);
    console.log("listMoneySendbyDayOfWeek:", listMoneySendByWeek);

    const totalMoney = checkPiggy.totalMoney;
    return {
      status: "success",
      message: "Get total money successfully",
      listMoneySendByMonth: listMoneySendByMonth,
      listMoneySendByWeek: listMoneySendByWeek,
      totalMoney: totalMoney,
    };
  } catch (error) {
    console.error("Error:", error);
    throw error;
  }
};

const getLogMoneySend = async (userId) => {
  try {
    const checkUser = await User.findOne({ _id: userId });
    if (!checkUser) {
      return {
        status: "error",
        message: "The user does not exist",
      };
    }

    const checkPiggy = await Piggy.findOne({ user: userId });
    if (!checkPiggy) {
      return {
        status: "error",
        message: "The piggy does not exist",
      };
    }

    const moneySend = checkPiggy.moneySend;
    return {
      status: "success",
      message: "Get log money send successfully",
      data: moneySend,
    };
  } catch (error) {
    console.error("Error:", error);
    throw error;
  }
};

module.exports = {
  //createUser,
  loginUser,
  logoutUser,
  resetPassword,
  verifyCode,
  updatePass,
  updateUser,
  decodeToken,
  deleteUser,
  getImage,
  getAllUser,
  getDetailsUser,
  deleteManyUser,
  getDetailsUserWithCart,
  sendMoney,
  getTotalMoney,
  getLogMoneySend
};
