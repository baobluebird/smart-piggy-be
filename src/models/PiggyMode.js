const mongoose = require('mongoose')

const piggySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    moneySend: [
      {
        money: { type: Number, required: true },
        time: { type: Date, required: true }
      }
    ],
    totalMoney : { type: Number, required: true }
  },
  {
    timestamps: true
  }
);

const Piggy = mongoose.model("Piggy", piggySchema);
module.exports = Piggy;