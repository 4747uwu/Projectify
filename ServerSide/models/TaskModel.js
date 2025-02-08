import mongoose from "mongoose";

const taskSchema = new mongoose.Schema(
  {
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: "Project", required: true },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    assignedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    title: { type: String, required: true },
    description: { type: String, default: "" },
    status: { type: String, enum: ["todo", "in-progress", "review", "completed"], default: "todo" },
    priority: { type: String, enum: ["low", "medium", "high"], default: "medium" },
    dueDate: { type: Date },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

export const Task = mongoose.model("Task", taskSchema);
