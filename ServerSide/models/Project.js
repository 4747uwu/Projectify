import mongoose from "mongoose";

const projectSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    description: { type: String, default: "" },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, // Project owner
    members: [
      {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        role: { type: String, enum: ["admin", "editor", "viewer"], default: "viewer" },
        joinedAt: { type: Date, default: Date.now },
        permissions: { type: [String], default: [] }, // Custom permissions
      },
    ],
    tasks: [{ type: mongoose.Schema.Types.ObjectId, ref: "Task" }], // Task references
    status: { type: String, enum: ["active", "completed", "archived"], default: "active" },
    priority: { type: String, enum: ["low", "medium", "high"], default: "medium" },
    deadline: { type: Date, required: true },
    progress: { type: Number, min: 0, max: 100, default: 0 },
    lastUpdated: { type: Date, default: Date.now },
    starredBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // Users who starred this project
    activityLog: [
      {
        action: String, // e.g., "Added a new task", "Changed project settings"
        timestamp: { type: Date, default: Date.now },
        triggeredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      },
    ],
  },
  { timestamps: true }
);

export default mongoose.model("Project", projectSchema);
