const todoRoutes = require("express").Router();
const dataModel = require("../Models/DataModel");
const userModel = require("../Models/Model");
const authMiddleware = require("../middleware/authMiddleware");

// Apply authentication middleware to all routes
todoRoutes.use(authMiddleware);

// Get all todos for the logged-in user
todoRoutes.get("/getTodo", async (req, res) => {
  try {
    console.log("Decoded User:", req.user);

    if (!req.user) {
      return res.status(401).json({ error: "User not authenticated" });
    }

    const { _id } = req.user;
    let user = await dataModel.findById(_id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user.todos);
  } catch (error) {
    console.error("Error fetching todos:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Add a new todo
todoRoutes.post("/postTodo", async (req, res) => {
  try {
    const { _id } = req.user;
    const newTodo = req.body;

    let user = await userModel.findById(_id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    await dataModel.findByIdAndUpdate(_id, { $push: { todos: newTodo } });
    res.json({ success: "Todo added successfully" });
  } catch (error) {
    console.error("Error posting todo:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Update todo status
todoRoutes.patch("/updateTodo/:todoId", async (req, res) => {
  try {
    const { todoId } = req.params;
    const { status } = req.body;

    const updatedTodo = await dataModel.findOneAndUpdate(
      { "todos.todoId": todoId },
      { $set: { "todos.$.status": status } },
      { new: true }
    );

    if (!updatedTodo) {
      return res.status(404).json({ error: "Todo not found" });
    }

    res.json({ success: "Todo updated successfully" });
  } catch (error) {
    console.error("Error updating todo:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Delete a todo
todoRoutes.delete("/deleteTodo/:todoId", async (req, res) => {
  try {
    const { _id } = req.user;
    const { todoId } = req.params;

    let user = await userModel.findById(_id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    await dataModel.findByIdAndUpdate(_id, { $pull: { todos: { todoId } } });

    res.json({ success: "Todo deleted successfully" });
  } catch (error) {
    console.error("Error deleting todo:", error);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = todoRoutes;
