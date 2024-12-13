import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk
import re

class ExpenseTrackerApp:
    def __init__(self, master):
        self.master = master
        master.title("Expense Tracker")
        master.geometry("900x800")
        master.configure(background="#A3C8F7")

        # Define fonts for better readability
        self.font_large = ("Arial", 14, "bold")
        self.font_medium = ("Arial", 12)
        self.font_small = ("Arial", 10)

        self.users = {}
        self.current_user = None
        self.salary = 0
        self.category_budgets = {}
        self.expenses = {}  # Dictionary to hold expenses
        self.spent_amounts = {} # Dictionary to track spent amounts per category
        
        self.categories = {
            "Food": ["Groceries", "Dining Out", "Snacks", "Alcohol", "Work Meals"],
            "Health": ["Gym Membership", "Doctor Visits", "Medicines"],
            "Utilities": ["Electricity", "Water", "Internet"],
            "Housing": ["Rent", "Home Insurance", "Home Maintenance", "Property Tax"],
            "Savings": ["Emergency Fund", "Investing Fund", "Home Fund"],
            "Others": ["Specify"]
        }

        self.create_widgets()
    def clear_screen(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def create_widgets(self):
        self.main_frame = tk.Frame(self.master, bg="#A3C8F7")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        self.show_login_screen()

    def show_login_screen(self):
        self.clear_screen()
        self.login_frame = tk.Frame(self.main_frame, bg="#A3C8F7")
        self.login_frame.pack(pady=100)

        # Username label and entry
        username_label = tk.Label(self.login_frame, text="Username:", font=self.font_medium, bg="#A3C8F7")
        username_label.grid(row=0, column=0, pady=10)
        self.username_entry = tk.Entry(self.login_frame, font=self.font_medium)
        self.username_entry.grid(row=0, column=1, pady=10)
        self.username_entry.bind("<Return>", lambda event: self.password_entry.focus())

        # Password label and entry
        password_label = tk.Label(self.login_frame, text="Password:", font=self.font_medium, bg="#A3C8F7")
        password_label.grid(row=1, column=0, pady=10)
        self.password_entry = tk.Entry(self.login_frame, show="*", font=self.font_medium)
        self.password_entry.grid(row=1, column=1, pady=10)
        self.password_entry.bind("<Return>", lambda event: self.login())

        # Show/hide password checkbutton
        show_password_button = tk.Checkbutton(self.login_frame, text="Show Password", command=self.toggle_password_visibility, bg="#A3C8F7", font=self.font_small)
        show_password_button.grid(row=2, columnspan=2, pady=5)

        # Login button
        login_button = tk.Button(self.login_frame, text="Login", command=self.login, font=self.font_medium, bg="#63B8FF", fg="white")
        login_button.grid(row=3, columnspan=2, pady=20)

        # Sign-up button
        signup_button = tk.Button(self.login_frame, text="Sign Up", command=self.show_signup_screen, font=self.font_medium, bg="#63B8FF", fg="white")
        signup_button.grid(row=4, columnspan=2, pady=10)
    def toggle_password_visibility(self):
        if self.password_entry.cget("show") == "*":
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def show_signup_screen(self):
        self.clear_screen()
        self.signup_frame = tk.Frame(self.main_frame, bg="#A3C8F7")
        self.signup_frame.pack(pady=100)

        # Title label
        signup_title_label = tk.Label(self.signup_frame, text="Create New Account", font=("Arial", 18, "bold"), bg="#A3C8F7")
        signup_title_label.grid(row=0, columnspan=2, pady=20)

        # Username label and entry
        new_username_label = tk.Label(self.signup_frame, text="Username:", font=self.font_medium, bg="#A3C8F7")
        new_username_label.grid(row=1, column=0, pady=10)
        self.new_username_entry = tk.Entry(self.signup_frame, font=self.font_medium)
        self.new_username_entry.grid(row=1, column=1, pady=10)
        self.new_username_entry.bind("<Return>", lambda event: self.new_password_entry.focus())

        # Password label and entry
        new_password_label = tk.Label(self.signup_frame, text="Password:", font=self.font_medium, bg="#A3C8F7")
        new_password_label.grid(row=2, column=0, pady=10)
        self.new_password_entry = tk.Entry(self.signup_frame, show="*", font=self.font_medium)
        self.new_password_entry.grid(row=2, column=1, pady=10)
        self.new_password_entry.bind("<Return>", lambda event: self.new_password_confirm_entry.focus())

        # Confirm password label and entry
        new_password_confirm_label = tk.Label(self.signup_frame, text="Confirm Password:", font=self.font_medium, bg="#A3C8F7")
        new_password_confirm_label.grid(row=3, column=0, pady=10)
        self.new_password_confirm_entry = tk.Entry(self.signup_frame, show="*", font=self.font_medium)
        self.new_password_confirm_entry.grid(row=3, column=1, pady=10)
        self.new_password_confirm_entry.bind("<Return>", lambda event: self.create_account())

        # Show/hide password checkbutton
        show_password_button_signup = tk.Checkbutton(self.signup_frame, text="Show Password", command=self.toggle_signup_password_visibility, bg="#A3C8F7", font=self.font_small)
        show_password_button_signup.grid(row=4, columnspan=2, pady=5)

        # Sign-up button
        signup_button = tk.Button(self.signup_frame, text="Sign Up", command=self.create_account, font=self.font_medium, bg="#63B8FF", fg="white")
        signup_button.grid(row=5, columnspan=2, pady=20)

        # Back to login button
        back_to_login_button = tk.Button(self.signup_frame, text="Back to Login", command=self.show_login_screen, font=self.font_medium, bg="#63B8FF", fg="white")
        back_to_login_button.grid(row=6, columnspan=2, pady=10)

    def toggle_signup_password_visibility(self):
        if self.new_password_entry.cget("show") == "*":
            self.new_password_entry.config(show="")
            self.new_password_confirm_entry.config(show="")
        else:
            self.new_password_entry.config(show="*")
            self.new_password_confirm_entry.config(show="*")
    def create_account(self):
        username = self.new_username_entry.get()
        password = self.new_password_entry.get()
        confirm_password = self.new_password_confirm_entry.get()

        if username and password:
            if password == confirm_password:
                if self.validate_password(password):
                    if username not in self.users:
                        self.users[username] = password
                        messagebox.showinfo("Success", "Account created successfully!")
                        self.show_login_screen()
                    else:
                        messagebox.showerror("Error", "Username already exists.")
                else:
                    messagebox.showerror("Error", "Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one number.")
            else:
                messagebox.showerror("Error", "Passwords do not match.")
        else:
            messagebox.showerror("Error", "Please fill in all fields.")

    def validate_password(self, password):
        if len(password) < 8:
            return False

        if not re.search("[A-Z]", password):
            return False

        if not re.search("[a-z]", password):
            return False

        if not re.search("[0-9]", password):
            return False

        return True

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username in self.users and self.users[username] == password:
            self.current_user = username
            self.show_salary_input_screen()
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    def show_salary_input_screen(self):
        self.clear_screen()

        # Salary input frame
        salary_input_frame = tk.Frame(self.main_frame, bg="#A3C8F7")
        salary_input_frame.pack(pady=50)

        # Welcome message
        welcome_label = tk.Label(salary_input_frame, text=f"Welcome, {self.current_user}!", font=("Arial", 18, "bold"), bg="#A3C8F7")
        welcome_label.grid(row=0, columnspan=2, pady=20)

        # Salary label and entry
        salary_label = tk.Label(salary_input_frame, text="Enter Salary:", font=self.font_medium, bg="#A3C8F7")
        salary_label.grid(row=1, column=0, pady=10)
        self.salary_entry = tk.Entry(salary_input_frame, font=self.font_medium)
        self.salary_entry.grid(row=1, column=1, pady=10)

        # Submit button
        submit_button = tk.Button(salary_input_frame, text="Submit", command=self.save_salary, font=self.font_medium, bg="#63B8FF", fg="white")
        submit_button.grid(row=2, columnspan=2, pady=20)

        # Return to dashboard button
        return_button = tk.Button(salary_input_frame, text="Return to Dashboard", command=self.show_dashboard_screen, font=self.font_medium, bg="#63B8FF", fg="white")
        return_button.grid(row=3, columnspan=2, pady=10)

        # Logout button
        logout_button = tk.Button(salary_input_frame, text="Logout", command=self.logout, font=self.font_medium, bg="#FF6347", fg="white")
        logout_button.grid(row=4, columnspan=2, pady=10)

    def save_salary(self):
        try:
            self.salary = float(self.salary_entry.get())
            self.update_budgets()
            self.show_dashboard_screen()
        except ValueError:
            messagebox.showerror("Error", "Invalid salary amount.")

    def update_budgets(self):
        if self.salary > 0:
            self.category_budgets = {category: self.salary / len(self.categories) for category in self.categories.keys()}
            self.spent_amounts = {category: 0 for category in self.categories.keys()}  # Initialize spent amounts
        else:
            self.category_budgets = {}
            self.spent_amounts = {}
    def show_dashboard_screen(self):
        self.clear_screen()
        dashboard_frame = tk.Frame(self.main_frame, bg="#A3C8F7")
        dashboard_frame.pack(pady=50)

        dashboard_title_label = tk.Label(dashboard_frame, text="Dashboard", font=self.font_large, bg="#A3C8F7")
        dashboard_title_label.grid(row=0, columnspan=2, pady=20)

        #Improved button placement
        add_expense_button = tk.Button(dashboard_frame, text="Add Expense", command=self.show_add_expense_screen, font=self.font_medium, bg="#63B8FF", fg="white")
        add_expense_button.grid(row=1, columnspan=2, pady=10)

        view_expenses_button = tk.Button(dashboard_frame, text="View Expenses", command=self.show_view_expenses_screen, font=self.font_medium, bg="#63B8FF", fg="white")
        view_expenses_button.grid(row=2, columnspan=2, pady=10)

        view_budget_button = tk.Button(dashboard_frame, text="View Budget", command=self.show_budget_window, font=self.font_medium, bg="#63B8FF", fg="white")
        view_budget_button.grid(row=3, columnspan=2, pady=10)

        logout_button = tk.Button(dashboard_frame, text="Logout", command=self.logout, font=self.font_medium, bg="#FF6347", fg="white")
        logout_button.grid(row=4, columnspan=2, pady=10)
    def show_add_expense_screen(self):
        self.clear_screen()

        add_expense_frame = tk.Frame(self.main_frame, bg="#A3C8F7")
        add_expense_frame.pack(pady=50)

        # Title label
        add_expense_title_label = tk.Label(add_expense_frame, text="Add Expense", font=("Arial", 18, "bold"), bg="#A3C8F7")
        add_expense_title_label.grid(row=0, columnspan=2, pady=20)

        # Category selection
        category_label = tk.Label(add_expense_frame, text="Category:", font=self.font_medium, bg="#A3C8F7")
        category_label.grid(row=1, column=0, pady=10)
        self.category_combobox = ttk.Combobox(add_expense_frame, values=list(self.categories.keys()), font=self.font_medium)
        self.category_combobox.grid(row=1, column=1, pady=10)

        # Subcategory selection
        subcategory_label = tk.Label(add_expense_frame, text="Subcategory:", font=self.font_medium, bg="#A3C8F7")
        subcategory_label.grid(row=2, column=0, pady=10)
        self.subcategory_combobox = ttk.Combobox(add_expense_frame, values=[], font=self.font_medium)
        self.subcategory_combobox.grid(row=2, column=1, pady=10)

        # Update subcategories when category is selected
        self.category_combobox.bind("<<ComboboxSelected>>", self.update_subcategories)
        # Amount entry
        amount_label = tk.Label(add_expense_frame, text="Amount:", font=self.font_medium, bg="#A3C8F7")
        amount_label.grid(row=3, column=0, pady=10)
        self.expense_entry = tk.Entry(add_expense_frame, font=self.font_medium)
        self.expense_entry.grid(row=3, column=1, pady=10)

        # Add expense button
        add_expense_button = tk.Button(add_expense_frame, text="Add Expense", command=self.add_expense, font=self.font_medium, bg="#63B8FF", fg="white")
        add_expense_button.grid(row=4, columnspan=2, pady=20)

        # Return to dashboard button
        return_button = tk.Button(add_expense_frame, text="Return to Dashboard", command=self.show_dashboard_screen, font=self.font_medium, bg="#63B8FF", fg="white")
        return_button.grid(row=5, columnspan=2, pady=10)
    def update_subcategories(self, event):
        category = self.category_combobox.get()
        subcategories = self.categories.get(category, [])
        self.subcategory_combobox['values'] = subcategories
        self.subcategory_combobox.set('')
    def add_expense(self):
        category = self.category_combobox.get()
        subcategory = self.subcategory_combobox.get()
        amount_str = self.expense_entry.get()

        if category and subcategory and amount_str:
            try:
                amount = float(amount_str)
                if amount <= 0:
                    raise ValueError("Amount must be positive.")
                expense_key = f"{category} - {subcategory}"
                if expense_key not in self.expenses:
                    self.expenses[expense_key] = []
                self.expenses[expense_key].append(amount)

                # Correct budget update
                self.spent_amounts[category] = self.spent_amounts.get(category, 0) + amount
                self.category_budgets[category] = self.category_budgets[category] - self.spent_amounts[category]

                messagebox.showinfo("Success", f"Expense added: ${amount}")
                self.show_dashboard_screen()
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid amount: {e}")
        else:
            messagebox.showerror("Error", "Please fill in all fields.")

    def logout(self):
        self.current_user = None
        self.salary = 0
        self.category_budgets = {}
        self.expenses = {}
        self.spent_amounts = {}
        self.show_login_screen()
        messagebox.showinfo("Success", "Logout successful!")

    def show_budget_window(self):
        self.clear_screen()

        # Budget window frame
        budget_frame = tk.Frame(self.main_frame, bg="#A3C8F7")
        budget_frame.pack(pady=50)

        # Title label
        budget_title_label = tk.Label(budget_frame, text="Allocated Budget", font=("Arial", 18, "bold"), bg="#A3C8F7")
        budget_title_label.grid(row=0, columnspan=2, pady=20)

        # Display allocated budgets
        row = 1
        for category, budget in self.category_budgets.items():
            budget_label = tk.Label(budget_frame, text=f"{category}: ${budget:.2f}", font=self.font_medium, bg="#A3C8F7")
            budget_label.grid(row=row, column=0, sticky="w", pady=10)
            row += 1

        # Return to dashboard button
        return_button = tk.Button(budget_frame, text="Return to Dashboard", command=self.show_dashboard_screen, font=self.font_medium, bg="#63B8FF", fg="white")
        return_button.grid(row=row, columnspan=2, pady=10)

        # Logout button
        logout_button = tk.Button(budget_frame, text="Logout", command=self.logout, font=self.font_medium, bg="#FF6347", fg="white")
        logout_button.grid(row=row + 1, columnspan=2, pady=10)

    def show_view_expenses_screen(self):
        self.clear_screen()
        view_expenses_frame = tk.Frame(self.main_frame, bg="#A3C8F7")
        view_expenses_frame.pack(pady=50)

        view_expenses_title_label = tk.Label(view_expenses_frame, text="View Expenses", font=("Arial", 18, "bold"), bg="#A3C8F7")
        view_expenses_title_label.grid(row=0, columnspan=2, pady=20)

        row = 1
        for category_subcategory, expenses in self.expenses.items():
            total_expenses = sum(expenses)
            category_label = tk.Label(view_expenses_frame, text=f"{category_subcategory}: ${total_expenses:.2f}", font=self.font_medium, bg="#A3C8F7")
            category_label.grid(row=row, column=0, sticky="w", pady=10)

            #Improved detail display
            for i, exp in enumerate(expenses):
                exp_label = tk.Label(view_expenses_frame, text=f"  Expense {i+1}: ${exp:.2f}", font=self.font_small, bg="#A3C8F7")
                exp_label.grid(row=row + i + 1, column=0, sticky="w", pady=2)

            update_button = tk.Button(view_expenses_frame, text="Update", command=lambda key=category_subcategory: self.update_expense(key), font=self.font_medium, bg="#63B8FF", fg="white")
            update_button.grid(row=row + len(expenses), column=1, padx=5, pady=10)

            delete_button = tk.Button(view_expenses_frame, text="Delete", command=lambda key=category_subcategory: self.delete_expense(key), font=self.font_medium, bg="#63B8FF", fg="white")
            delete_button.grid(row=row + len(expenses), column=2, padx=5, pady=10)

            row += len(expenses) + 1

        return_button = tk.Button(view_expenses_frame, text="Return to Dashboard", command=self.show_dashboard_screen, font=self.font_medium, bg="#63B8FF", fg="white")
        return_button.grid(row=row, columnspan=3, pady=10)

        logout_button = tk.Button(view_expenses_frame, text="Logout", command=self.logout, font=self.font_medium, bg="#FF6347", fg="white")
        logout_button.grid(row=row + 1, columnspan=3, pady=10)

    def update_expense(self, key):
        try:
            amount_to_update = simpledialog.askfloat("Update Expense", f"Enter new amount for {key}:", initialvalue=sum(self.expenses[key]))
            if amount_to_update is not None:
                if amount_to_update <= 0:
                    raise ValueError("Amount must be positive.")
                old_amount = sum(self.expenses[key])
                difference = amount_to_update - old_amount
                self.expenses[key] = [amount_to_update]
                category = key.split(" - ")[0]
                self.spent_amounts[category] += difference
                self.category_budgets[category] = self.category_budgets[category] + old_amount - self.spent_amounts[category]
                messagebox.showinfo("Success", f"Expense for {key} updated successfully.")
                self.show_view_expenses_screen()
                self.show_budget_window()
        except (KeyError, ValueError) as e:
            messagebox.showerror("Error", f"Error updating expense: {e}")


    def delete_expense(self, key):
        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the expense '{key}'?"):
            try:
                amount_deleted = sum(self.expenses[key])
                del self.expenses[key]
                category = key.split(" - ")[0]
                self.spent_amounts[category] -= amount_deleted
                self.category_budgets[category] = self.category_budgets[category] + amount_deleted
                messagebox.showinfo("Success", f"Expense '{key}' deleted successfully.")
                self.show_view_expenses_screen()
                self.show_budget_window()
            except KeyError:
                messagebox.showerror("Error", f"Expense '{key}' not found.")

def run_expense_tracker():
    root = tk.Tk()
    app = ExpenseTrackerApp(root)
    root.mainloop()

if __name__ == "__main__":
    run_expense_tracker()