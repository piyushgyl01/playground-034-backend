const mongoose = require("mongoose");

const postSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120,
    },
    content: {
      type: String,
      required: true,
      trim: true,
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Pg34User",
      required: true,
    },
    tags: {
      type: [String],
      default: [],
      trim: true,
      maxlength: 20,
    },
    featuredImage: {
      url: String,
      thumbnail: String,
    },
    publishedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Pg34Post", postSchema);
