import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    name:{type:String, required:true},
    email:{type:String, required:true, unique:true},
    password:{type:String, required:true},
    profilePicture:{type:String, default:""},
    role:{type:String, enum:["admin","member","viewer"], default:"user"},
    authProvider:{type:String, enum:["email","google"], default:"email"},
    googleId:{type:String, default:""},
    bio: { type: String, default: "" },
    isVerified: { type: Boolean, default: false }, // Email verified status
    status: { type: String, enum: ["active", "suspended", "deleted"], default: "active" }, // Account status


    projects: [
  {
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: "Project" }, 
    name: { type: String, required: true }, 
    deadline: { type: Date, required: true }, 
    priority: { type: String, enum: ["low", "medium", "high"], default: "medium" }, 
    role: { type: String, enum: ["owner", "admin", "editor", "viewer"] }, 
    joinedAt: { type: Date, default: Date.now }, 

    status: { type: String, enum: ["active", "completed", "archived"], default: "active" }, // Project status
    progress: { type: Number, min: 0, max: 100, default: 0 }, // Project completion percentage
    lastActiveAt: { type: Date, default: Date.now }, // Last activity by the user in this project
    permissions: { type: [String], default: [] }, // Custom permissions for the user in the project
    starred: { type: Boolean, default: false }, // Whether the user has marked this project as important
  },
],


      invitations: [
  {
    invitationId: { type: mongoose.Schema.Types.ObjectId, ref: "Invitation" }, 
    inviterId: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // User who sent the invite
    status: { type: String, enum: ["pending", "accepted", "declined"], default: "pending" },
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: "Project" }, // Project for which the invitation was sent
    role: { type: String, enum: ["admin", "editor", "viewer"] }, // Role assigned in the project if accepted
    sentAt: { type: Date, default: Date.now }, // When the invitation was sent
    respondedAt: { type: Date }, // When the invite was accepted/declined
    message: { type: String, default: "" }, // Custom message with the invite
  },
],

    notifications: [
  {
    message: { type: String, required: true }, // Notification text
    type: { type: String, enum: ["task", "mention", "deadline", "general", "invitation", "update"] }, // More categories
    isRead: { type: Boolean, default: false }, // Whether the notification has been seen
    createdAt: { type: Date, default: Date.now }, // Timestamp when the notification was created
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: "Project" }, // Related project (if applicable)
    triggeredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // Who triggered this notification
    actionUrl: { type: String, default: "" }, // URL to direct the user (e.g., task, discussion, project page)
    priority: { type: String, enum: ["low", "medium", "high"], default: "medium" }, // Importance level
    expiresAt: { type: Date }, // Expiration date for temporary notifications
  },
],

tasks: [{
    taskId: { type: mongoose.Schema.Types.ObjectId, ref: "Task" }, // Task reference
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: "Project" }, // Project reference
    title: { type: String, required: true }, // Task title
    description: { type: String, default: "" }, // Task description
    status: { type: String, enum: ["todo", "in-progress", "review", "completed"], default: "todo" },
    priority: { type: String, enum: ["low", "medium", "high"], default: "medium" },
    dueDate: { type: Date }, // Task deadline
    assignedAt: { type: Date, default: Date.now },
    lastUpdated: { type: Date, default: Date.now },
    assignedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // User who assigned the task

}],


    preferences: {
      darkMode: { type: Boolean, default: false },
      notificationSettings: {
        emailNotifications: { type: Boolean, default: true },
        pushNotifications: { type: Boolean, default: true },
      },

       dashboardSettings: {
        defaultView: { type: String, enum: ["list", "grid", "kanban"], default: "kanban" }, // Default dashboard view
        showCompletedTasks: { type: Boolean, default: true }, // Show/hide completed tasks
        showDeadlines: { type: Boolean, default: true }, // Display deadlines in task view
        },
    },

    resetPasswordToken: { type: String, default: null },
    resetPasswordExpires: { type: Date, default: null },
  },
  { timestamps: true }


);

export default mongoose.models.User || mongoose.model("User", userSchema);