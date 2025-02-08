const invitationSchema = new mongoose.Schema(
  {
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: "Project", required: true },
    inviterId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    inviteeEmail: { type: String, required: true },
    role: { type: String, enum: ["admin", "editor", "viewer"], required: true },
    status: { type: String, enum: ["pending", "accepted", "declined"], default: "pending" },
    sentAt: { type: Date, default: Date.now },
    respondedAt: { type: Date },
    message: { type: String, default: "" },
  },
  { timestamps: true }
);

export const Invitation = mongoose.model("Invitation", invitationSchema);
