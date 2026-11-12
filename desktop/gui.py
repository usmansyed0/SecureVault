"""
SecureVault Desktop Modern GUI
Rich Cyber Obsidian interface providing complete 5-pillar vault experience.
"""

from __future__ import annotations

import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional
import uuid

from desktop.vault_manager import (
    DesktopVaultManager,
    DocumentItem,
    DocumentPage,
    NoteItem,
    PasswordGenerator,
    PasswordItem,
    PasswordStrengthEvaluator,
)

# Cyber Obsidian Palette matching Android SecureVaultTheme
COLOR_BG = "#0A0E1A"
COLOR_SURFACE = "#131B2E"
COLOR_SURFACE_VARIANT = "#1C2740"
COLOR_PRIMARY = "#4E80EE"
COLOR_ACCENT = "#00E5FF"
COLOR_TEXT = "#F0F4FF"
COLOR_TEXT_SECONDARY = "#8A99B5"
COLOR_SUCCESS = "#00E676"
COLOR_WARNING = "#FFB300"
COLOR_ERROR = "#FF3366"


class SecureVaultAppGUI:
    def __init__(self, root: tk.Tk, vault: DesktopVaultManager):
        self.root = root
        self.vault = vault
        self.root.title("SecureVault — Personal Encrypted Safe")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)
        self.root.configure(bg=COLOR_BG)

        self.vault.on_lock_callback = self._on_vault_locked
        self._clipboard_clear_timer: Optional[threading.Timer] = None

        self._init_styles()
        self._build_ui()
        self._start_touch_tracker()

    def _init_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "TFrame",
            background=COLOR_BG,
        )
        style.configure(
            "Card.TFrame",
            background=COLOR_SURFACE,
            relief="flat",
        )
        style.configure(
            "Sidebar.TFrame",
            background=COLOR_SURFACE,
        )
        style.configure(
            "TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Card.TLabel",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Primary.TButton",
            background=COLOR_PRIMARY,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
            padding=8,
        )
        style.map("Primary.TButton", background=[("active", COLOR_ACCENT), ("disabled", COLOR_SURFACE_VARIANT)])
        style.configure(
            "Danger.TButton",
            background=COLOR_ERROR,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
            padding=6,
        )

    def _start_touch_tracker(self) -> None:
        self.root.bind_all("<Any-KeyPress>", lambda e: self.vault.touch())
        self.root.bind_all("<Any-ButtonPress>", lambda e: self.vault.touch())

        def check_inactivity():
            if self.vault.is_unlocked():
                rem = max(0, int(self.vault.inactivity_timeout_s - (time.time() - self.vault.last_touch)))
                if rem == 0:
                    self.vault.lock()
            self.root.after(1000, check_inactivity)

        self.root.after(1000, check_inactivity)

    def _on_vault_locked(self) -> None:
        self.show_lock_screen()

    def _copy_with_auto_clear(self, text: str, label: str = "Password") -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

        if self._clipboard_clear_timer:
            self._clipboard_clear_timer.cancel()

        def clear():
            try:
                self.root.clipboard_clear()
            except Exception:
                pass

        self._clipboard_clear_timer = threading.Timer(30.0, clear)
        self._clipboard_clear_timer.daemon = True
        self._clipboard_clear_timer.start()

        messagebox.showinfo("Clipboard", f"{label} copied to clipboard.\nWill auto-clear in 30 seconds.")

    def _build_ui(self) -> None:
        self.container = tk.Frame(self.root, bg=COLOR_BG)
        self.container.pack(fill="both", expand=True)
        self.show_lock_screen()

    def clear_container(self) -> None:
        for widget in self.container.winfo_children():
            widget.destroy()

    # =========================================================================
    # 1. LOCK SCREEN
    # =========================================================================
    def show_lock_screen(self) -> None:
        self.clear_container()

        center_card = tk.Frame(self.container, bg=COLOR_SURFACE, padx=36, pady=36)
        center_card.place(relx=0.5, rely=0.5, anchor="center")

        # Shield Logo
        tk.Label(center_card, text="🛡️", font=("Segoe UI", 36), bg=COLOR_SURFACE, fg=COLOR_ACCENT).pack()
        tk.Label(
            center_card,
            text="SECURE VAULT",
            font=("Segoe UI", 18, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT,
        ).pack(pady=(4, 2))
        tk.Label(
            center_card,
            text="Personal Encrypted Digital Safe",
            font=("Segoe UI", 10),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
        ).pack(pady=(0, 20))

        failed, rem = self.vault.pin_manager.get_status()
        if rem > 0:
            tk.Label(
                center_card,
                text=f"Locked out for {rem}s",
                font=("Segoe UI", 10, "bold"),
                bg=COLOR_SURFACE,
                fg=COLOR_ERROR,
            ).pack(pady=4)

        if self.vault.pin_manager.has_pin() and rem == 0:
            pin_frame = tk.Frame(center_card, bg=COLOR_SURFACE)
            pin_frame.pack(pady=10)

            tk.Label(pin_frame, text="Enter 4–6 Digit Daily PIN", font=("Segoe UI", 10, "bold"), bg=COLOR_SURFACE, fg=COLOR_TEXT).pack()
            pin_entry = tk.Entry(pin_frame, show="•", font=("Segoe UI", 14), justify="center", width=12)
            pin_entry.pack(pady=6)
            pin_entry.focus()

            def on_pin_submit():
                pin = pin_entry.get().strip()
                try:
                    self.vault.unlock_with_pin(pin)
                    self.show_main_screen()
                except Exception as e:
                    messagebox.showerror("PIN Unlock Failed", str(e))
                    self.show_lock_screen()

            tk.Button(
                pin_frame,
                text="Unlock with PIN",
                font=("Segoe UI", 10, "bold"),
                bg=COLOR_PRIMARY,
                fg=COLOR_TEXT,
                activebackground=COLOR_ACCENT,
                relief="flat",
                command=on_pin_submit,
                padx=16,
                pady=6,
            ).pack(pady=6)

            pin_entry.bind("<Return>", lambda e: on_pin_submit())

        # Master Password Accordion / Section
        sep = tk.Frame(center_card, height=1, bg=COLOR_SURFACE_VARIANT)
        sep.pack(fill="x", pady=16)

        tk.Label(
            center_card,
            text="Unlock with Master Password",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
        ).pack(pady=(0, 8))

        cred_frame = tk.Frame(center_card, bg=COLOR_SURFACE)
        cred_frame.pack()

        tk.Label(cred_frame, text="Account Email:", bg=COLOR_SURFACE, fg=COLOR_TEXT_SECONDARY).grid(row=0, column=0, sticky="w", pady=4)
        email_entry = tk.Entry(cred_frame, width=24, font=("Segoe UI", 10))
        email_entry.grid(row=0, column=1, pady=4, padx=6)

        tk.Label(cred_frame, text="Master Password:", bg=COLOR_SURFACE, fg=COLOR_TEXT_SECONDARY).grid(row=1, column=0, sticky="w", pady=4)
        pass_entry = tk.Entry(cred_frame, show="•", width=24, font=("Segoe UI", 10))
        pass_entry.grid(row=1, column=1, pady=4, padx=6)

        def on_master_submit():
            email = email_entry.get().strip()
            mp = pass_entry.get()
            if not email or not mp:
                messagebox.showwarning("Input Required", "Please enter your Account Email and Master Password.")
                return
            try:
                self.vault.unlock_with_master_password(email, mp)
                self.show_main_screen()
            except Exception as e:
                messagebox.showerror("Master Unlock Failed", f"Could not authenticate vault: {e}")

        tk.Button(
            center_card,
            text="Unlock Account",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_SURFACE_VARIANT,
            fg=COLOR_TEXT,
            activebackground=COLOR_PRIMARY,
            relief="flat",
            command=on_master_submit,
            padx=14,
            pady=6,
        ).pack(pady=10)

    # =========================================================================
    # 2. MAIN APPLICATION INTERFACE
    # =========================================================================
    def show_main_screen(self) -> None:
        self.clear_container()

        # Top Bar
        top_bar = tk.Frame(self.container, bg=COLOR_SURFACE, height=54, padx=20)
        top_bar.pack(fill="x", side="top")

        tk.Label(top_bar, text="🛡️ SECURE VAULT", font=("Segoe UI", 13, "bold"), bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(side="left", pady=12)
        tk.Label(top_bar, text="• Active Encrypted Session", font=("Segoe UI", 9), bg=COLOR_SURFACE, fg=COLOR_SUCCESS).pack(side="left", padx=10, pady=14)

        # Quick Actions
        tk.Button(
            top_bar,
            text="🔒 Lock Vault",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_SURFACE_VARIANT,
            fg=COLOR_TEXT,
            relief="flat",
            command=self.vault.lock,
            padx=10,
            pady=4,
        ).pack(side="right", padx=6, pady=10)

        # Content Layout: Sidebar + Main Area
        body = tk.Frame(self.container, bg=COLOR_BG)
        body.pack(fill="both", expand=True)

        # Sidebar
        sidebar = tk.Frame(body, bg=COLOR_SURFACE, width=200, padx=10, pady=16)
        sidebar.pack(fill="y", side="left")

        self.main_content = tk.Frame(body, bg=COLOR_BG, padx=20, pady=20)
        self.main_content.pack(fill="both", expand=True, side="right")

        tabs = [
            ("🏠 Dashboard", self.show_dashboard_tab),
            ("🔑 Passwords", self.show_passwords_tab),
            ("📄 Documents", self.show_documents_tab),
            ("📓 Private Diary", self.show_notes_tab),
            ("🖼️ Image to PDF", self.show_image_to_pdf_tab),
            ("🔗 Share Center", self.show_shares_tab),
            ("⚙️ Settings", self.show_settings_tab),
        ]

        for label, cmd in tabs:
            btn = tk.Button(
                sidebar,
                text=label,
                font=("Segoe UI", 10),
                bg=COLOR_SURFACE,
                fg=COLOR_TEXT,
                activebackground=COLOR_SURFACE_VARIANT,
                activeforeground=COLOR_ACCENT,
                anchor="w",
                relief="flat",
                command=cmd,
                padx=12,
                pady=8,
            )
            btn.pack(fill="x", pady=2)

        self.show_dashboard_tab()

    def _clear_main_content(self) -> None:
        for w in self.main_content.winfo_children():
            w.destroy()

    # --- TAB: DASHBOARD ---
    def show_dashboard_tab(self) -> None:
        self._clear_main_content()

        tk.Label(self.main_content, text="Secure Vault Dashboard", font=("Segoe UI", 18, "bold"), fg=COLOR_TEXT, bg=COLOR_BG).pack(anchor="w", pady=(0, 16))

        # Quick Stats Row
        stats_frame = tk.Frame(self.main_content, bg=COLOR_BG)
        stats_frame.pack(fill="x", pady=(0, 24))

        stats = [
            ("Passwords", len(self.vault.passwords), COLOR_PRIMARY),
            ("Documents", len(self.vault.documents), COLOR_ACCENT),
            ("Diary Notes", len(self.vault.notes), "#9D4EDD"),
            ("Active Shares", len(self.vault.active_shares), COLOR_SUCCESS),
        ]

        for title, count, color in stats:
            card = tk.Frame(stats_frame, bg=COLOR_SURFACE, padx=20, pady=16, width=180)
            card.pack(side="left", padx=8)
            tk.Label(card, text=str(count), font=("Segoe UI", 24, "bold"), fg=color, bg=COLOR_SURFACE).pack(anchor="w")
            tk.Label(card, text=title, font=("Segoe UI", 10), fg=COLOR_TEXT_SECONDARY, bg=COLOR_SURFACE).pack(anchor="w")

        # 5 Primary Categories Cards
        tk.Label(self.main_content, text="Vault Modules", font=("Segoe UI", 14, "bold"), fg=COLOR_TEXT, bg=COLOR_BG).pack(anchor="w", pady=(8, 12))

        modules_frame = tk.Frame(self.main_content, bg=COLOR_BG)
        modules_frame.pack(fill="both", expand=True)

        modules = [
            ("🔑 PASSWORDS", "Logins, apps & accounts", self.show_passwords_tab),
            ("📄 DOCUMENTS", "Encrypted digital safe files", self.show_documents_tab),
            ("📓 PRIVATE DIARY", "Secure personal journals & notes", self.show_notes_tab),
            ("🖼️ IMAGE TO PDF", "Combine & export multi-page PDFs", self.show_image_to_pdf_tab),
            ("🔗 SECURE SHARE", "Zero-knowledge ephemeral links", self.show_shares_tab),
        ]

        for i, (title, desc, cmd) in enumerate(modules):
            m_card = tk.Frame(modules_frame, bg=COLOR_SURFACE, padx=16, pady=16, cursor="hand2")
            m_card.grid(row=i // 3, column=i % 3, padx=8, pady=8, sticky="nsew")
            tk.Label(m_card, text=title, font=("Segoe UI", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_SURFACE).pack(anchor="w")
            tk.Label(m_card, text=desc, font=("Segoe UI", 9), fg=COLOR_TEXT_SECONDARY, bg=COLOR_SURFACE).pack(anchor="w", pady=(4, 10))
            tk.Button(
                m_card,
                text="Open →",
                font=("Segoe UI", 9, "bold"),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_ACCENT,
                relief="flat",
                command=cmd,
                padx=8,
                pady=3,
            ).pack(anchor="e")

    # --- TAB: PASSWORDS ---
    def show_passwords_tab(self) -> None:
        self._clear_main_content()

        header = tk.Frame(self.main_content, bg=COLOR_BG)
        header.pack(fill="x", pady=(0, 16))

        tk.Label(header, text="Passwords Vault", font=("Segoe UI", 16, "bold"), fg=COLOR_TEXT, bg=COLOR_BG).pack(side="left")

        tk.Button(
            header,
            text="+ Add Password",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_PRIMARY,
            fg=COLOR_TEXT,
            relief="flat",
            command=self._dialog_add_edit_password,
            padx=12,
            pady=6,
        ).pack(side="right")

        # Password items list
        items_frame = tk.Frame(self.main_content, bg=COLOR_BG)
        items_frame.pack(fill="both", expand=True)

        if not self.vault.passwords:
            tk.Label(items_frame, text="No passwords stored yet. Click '+ Add Password' above.", fg=COLOR_TEXT_SECONDARY, bg=COLOR_BG).pack(pady=40)
            return

        for p in self.vault.passwords.values():
            p_card = tk.Frame(items_frame, bg=COLOR_SURFACE, padx=16, pady=12)
            p_card.pack(fill="x", pady=6)

            info = tk.Frame(p_card, bg=COLOR_SURFACE)
            info.pack(side="left", fill="x", expand=True)

            tk.Label(info, text=p.title, font=("Segoe UI", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_SURFACE).pack(anchor="w")
            tk.Label(info, text=f"Username: {p.username}  •  Category: {p.category}", font=("Segoe UI", 9), fg=COLOR_TEXT_SECONDARY, bg=COLOR_SURFACE).pack(anchor="w")

            actions = tk.Frame(p_card, bg=COLOR_SURFACE)
            actions.pack(side="right")

            tk.Button(
                actions,
                text="Copy User",
                font=("Segoe UI", 8),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_TEXT,
                relief="flat",
                command=lambda u=p.username: self._copy_with_auto_clear(u, "Username"),
                padx=6,
                pady=2,
            ).pack(side="left", padx=2)

            tk.Button(
                actions,
                text="Copy Pwd",
                font=("Segoe UI", 8, "bold"),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_ACCENT,
                relief="flat",
                command=lambda pwd=p.password: self._copy_with_auto_clear(pwd, "Password"),
                padx=6,
                pady=2,
            ).pack(side="left", padx=2)

            tk.Button(
                actions,
                text="Share",
                font=("Segoe UI", 8),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_SUCCESS,
                relief="flat",
                command=lambda item=p: self._share_item(asdict(item)),
                padx=6,
                pady=2,
            ).pack(side="left", padx=2)

            tk.Button(
                actions,
                text="🗑️",
                font=("Segoe UI", 8),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_ERROR,
                relief="flat",
                command=lambda pid=p.id: self._delete_password(pid),
                padx=6,
                pady=2,
            ).pack(side="left", padx=2)

    def _delete_password(self, pid: str) -> None:
        if messagebox.askyesno("Delete", "Are you sure you want to delete this password entry?"):
            self.vault.delete_password(pid)
            self.show_passwords_tab()

    def _dialog_add_edit_password(self, existing: Optional[PasswordItem] = None) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Add / Edit Password" if not existing else "Edit Password")
        dlg.geometry("450x420")
        dlg.configure(bg=COLOR_SURFACE, padx=20, pady=20)
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(dlg, text="Account Title:", bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(anchor="w")
        t_entry = tk.Entry(dlg, width=36, font=("Segoe UI", 10))
        t_entry.pack(fill="x", pady=(2, 8))
        if existing:
            t_entry.insert(0, existing.title)

        tk.Label(dlg, text="Username / Email:", bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(anchor="w")
        u_entry = tk.Entry(dlg, width=36, font=("Segoe UI", 10))
        u_entry.pack(fill="x", pady=(2, 8))
        if existing:
            u_entry.insert(0, existing.username)

        tk.Label(dlg, text="Password:", bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(anchor="w")
        pwd_box = tk.Frame(dlg, bg=COLOR_SURFACE)
        pwd_box.pack(fill="x", pady=(2, 8))
        p_entry = tk.Entry(pwd_box, width=28, font=("Segoe UI", 10))
        p_entry.pack(side="left", fill="x", expand=True)
        if existing:
            p_entry.insert(0, existing.password)

        def generate_pwd():
            generated = PasswordGenerator.generate(18)
            p_entry.delete(0, "end")
            p_entry.insert(0, generated)

        tk.Button(pwd_box, text="⚡ Gen", bg=COLOR_SURFACE_VARIANT, fg=COLOR_ACCENT, relief="flat", command=generate_pwd, padx=6).pack(side="right", padx=4)

        tk.Label(dlg, text="Website URL (optional):", bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(anchor="w")
        w_entry = tk.Entry(dlg, width=36, font=("Segoe UI", 10))
        w_entry.pack(fill="x", pady=(2, 14))
        if existing:
            w_entry.insert(0, existing.website)

        def save():
            title = t_entry.get().strip()
            username = u_entry.get().strip()
            pwd = p_entry.get()
            if not title or not pwd:
                messagebox.showwarning("Required", "Title and Password are required.")
                return
            item = PasswordItem(
                id=existing.id if existing else str(uuid.uuid4()),
                title=title,
                username=username,
                password=pwd,
                website=w_entry.get().strip(),
            )
            self.vault.save_password(item)
            dlg.destroy()
            self.show_passwords_tab()

        tk.Button(dlg, text="Save Password", font=("Segoe UI", 10, "bold"), bg=COLOR_PRIMARY, fg=COLOR_TEXT, relief="flat", command=save, pady=6).pack(fill="x", pady=10)

    # --- TAB: DOCUMENTS ---
    def show_documents_tab(self) -> None:
        self._clear_main_content()

        header = tk.Frame(self.main_content, bg=COLOR_BG)
        header.pack(fill="x", pady=(0, 16))

        tk.Label(header, text="Documents Vault", font=("Segoe UI", 16, "bold"), fg=COLOR_TEXT, bg=COLOR_BG).pack(side="left")

        tk.Button(
            header,
            text="+ Import Document",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_PRIMARY,
            fg=COLOR_TEXT,
            relief="flat",
            command=self._import_document,
            padx=12,
            pady=6,
        ).pack(side="right")

        items_frame = tk.Frame(self.main_content, bg=COLOR_BG)
        items_frame.pack(fill="both", expand=True)

        if not self.vault.documents:
            tk.Label(items_frame, text="No documents stored yet. Click '+ Import Document' or use 'Image to PDF' module.", fg=COLOR_TEXT_SECONDARY, bg=COLOR_BG).pack(pady=40)
            return

        for doc in self.vault.documents.values():
            d_card = tk.Frame(items_frame, bg=COLOR_SURFACE, padx=16, pady=12)
            d_card.pack(fill="x", pady=6)

            info = tk.Frame(d_card, bg=COLOR_SURFACE)
            info.pack(side="left", fill="x", expand=True)

            tk.Label(info, text=doc.title, font=("Segoe UI", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_SURFACE).pack(anchor="w")
            tk.Label(info, text=f"Category: {doc.category}  •  Pages: {len(doc.pages)}", font=("Segoe UI", 9), fg=COLOR_TEXT_SECONDARY, bg=COLOR_SURFACE).pack(anchor="w")

            actions = tk.Frame(d_card, bg=COLOR_SURFACE)
            actions.pack(side="right")

            tk.Button(
                actions,
                text="Share",
                font=("Segoe UI", 8),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_SUCCESS,
                relief="flat",
                command=lambda item=doc: self._share_item(asdict(item)),
                padx=6,
                pady=2,
            ).pack(side="left", padx=2)

            tk.Button(
                actions,
                text="🗑️",
                font=("Segoe UI", 8),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_ERROR,
                relief="flat",
                command=lambda did=doc.id: self._delete_document(did),
                padx=6,
                pady=2,
            ).pack(side="left", padx=2)

    def _delete_document(self, did: str) -> None:
        if messagebox.askyesno("Delete", "Are you sure you want to delete this document?"):
            self.vault.delete_document(did)
            self.show_documents_tab()

    def _import_document(self) -> None:
        paths = filedialog.askopenfilenames(title="Select Document Images or PDF", filetypes=[("Images & PDFs", "*.jpg *.jpeg *.png *.pdf")])
        if not paths:
            return
        title = os.path.splitext(os.path.basename(paths[0]))[0]
        pages = [DocumentPage(page_id=str(uuid.uuid4()), page_number=i + 1, title_hint=os.path.basename(p)) for i, p in enumerate(paths)]
        doc = DocumentItem(
            id=str(uuid.uuid4()),
            title=title.replace("_", " ").title(),
            pages=pages,
        )
        self.vault.save_document(doc)
        self.show_documents_tab()

    # --- TAB: NOTES & PRIVATE DIARY ---
    def show_notes_tab(self) -> None:
        self._clear_main_content()

        header = tk.Frame(self.main_content, bg=COLOR_BG)
        header.pack(fill="x", pady=(0, 16))

        tk.Label(header, text="Private Diary & Notes", font=("Segoe UI", 16, "bold"), fg=COLOR_TEXT, bg=COLOR_BG).pack(side="left")

        tk.Button(
            header,
            text="+ New Note / Journal",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_PRIMARY,
            fg=COLOR_TEXT,
            relief="flat",
            command=self._dialog_add_edit_note,
            padx=12,
            pady=6,
        ).pack(side="right")

        items_frame = tk.Frame(self.main_content, bg=COLOR_BG)
        items_frame.pack(fill="both", expand=True)

        if not self.vault.notes:
            tk.Label(items_frame, text="No diary entries or notes yet. Click '+ New Note / Journal' to begin.", fg=COLOR_TEXT_SECONDARY, bg=COLOR_BG).pack(pady=40)
            return

        for note in self.vault.notes.values():
            n_card = tk.Frame(items_frame, bg=COLOR_SURFACE, padx=16, pady=12)
            n_card.pack(fill="x", pady=6)

            info = tk.Frame(n_card, bg=COLOR_SURFACE)
            info.pack(side="left", fill="x", expand=True)

            tk.Label(info, text=note.title, font=("Segoe UI", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_SURFACE).pack(anchor="w")
            snippet = note.content[:70] + "..." if len(note.content) > 70 else note.content
            tk.Label(info, text=snippet, font=("Segoe UI", 9), fg=COLOR_TEXT_SECONDARY, bg=COLOR_SURFACE).pack(anchor="w", pady=(2, 0))

            actions = tk.Frame(n_card, bg=COLOR_SURFACE)
            actions.pack(side="right")

            tk.Button(
                actions,
                text="Edit",
                font=("Segoe UI", 8),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_TEXT,
                relief="flat",
                command=lambda item=note: self._dialog_add_edit_note(item),
                padx=6,
                pady=2,
            ).pack(side="left", padx=2)

            tk.Button(
                actions,
                text="Share",
                font=("Segoe UI", 8),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_SUCCESS,
                relief="flat",
                command=lambda item=note: self._share_item(asdict(item)),
                padx=6,
                pady=2,
            ).pack(side="left", padx=2)

            tk.Button(
                actions,
                text="🗑️",
                font=("Segoe UI", 8),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_ERROR,
                relief="flat",
                command=lambda nid=note.id: self._delete_note(nid),
                padx=6,
                pady=2,
            ).pack(side="left", padx=2)

    def _delete_note(self, nid: str) -> None:
        if messagebox.askyesno("Delete", "Are you sure you want to delete this diary entry?"):
            self.vault.delete_note(nid)
            self.show_notes_tab()

    def _dialog_add_edit_note(self, existing: Optional[NoteItem] = None) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Private Diary & Note Entry")
        dlg.geometry("520x480")
        dlg.configure(bg=COLOR_SURFACE, padx=20, pady=20)
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(dlg, text="Title / Journal Date:", bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(anchor="w")
        t_entry = tk.Entry(dlg, width=42, font=("Segoe UI", 10))
        t_entry.pack(fill="x", pady=(2, 8))
        if existing:
            t_entry.insert(0, existing.title)
        else:
            t_entry.insert(0, time.strftime("%A, %B %d, %Y"))

        tk.Label(dlg, text="Private Entry Content:", bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(anchor="w")
        c_text = tk.Text(dlg, height=12, width=42, font=("Segoe UI", 10), bg=COLOR_BG, fg=COLOR_TEXT, insertbackground=COLOR_ACCENT)
        c_text.pack(fill="both", expand=True, pady=(2, 10))
        if existing:
            c_text.insert("1.0", existing.content)

        def save():
            title = t_entry.get().strip()
            content = c_text.get("1.0", "end-1c")
            if not title:
                messagebox.showwarning("Required", "Title is required.")
                return
            item = NoteItem(
                id=existing.id if existing else str(uuid.uuid4()),
                title=title,
                content=content,
            )
            self.vault.save_note(item)
            dlg.destroy()
            self.show_notes_tab()

        tk.Button(dlg, text="Save Entry", font=("Segoe UI", 10, "bold"), bg=COLOR_PRIMARY, fg=COLOR_TEXT, relief="flat", command=save, pady=6).pack(fill="x")

    # --- TAB: IMAGE TO PDF CONVERTER ---
    def show_image_to_pdf_tab(self) -> None:
        self._clear_main_content()

        tk.Label(self.main_content, text="Image to PDF Converter", font=("Segoe UI", 16, "bold"), fg=COLOR_TEXT, bg=COLOR_BG).pack(anchor="w", pady=(0, 16))

        card = tk.Frame(self.main_content, bg=COLOR_SURFACE, padx=24, pady=24)
        card.pack(fill="both", expand=True)

        tk.Label(card, text="Select Images to Merge into Encrypted PDF", font=("Segoe UI", 11, "bold"), bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(anchor="w")
        tk.Label(card, text="Supports JPG, PNG, and multiple image selection.", font=("Segoe UI", 9), bg=COLOR_SURFACE, fg=COLOR_TEXT_SECONDARY).pack(anchor="w", pady=(2, 12))

        selected_files: List[str] = []
        files_listbox = tk.Listbox(card, height=6, bg=COLOR_BG, fg=COLOR_TEXT, selectbackground=COLOR_PRIMARY)
        files_listbox.pack(fill="x", pady=6)

        def add_images():
            paths = filedialog.askopenfilenames(title="Select Images", filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp")])
            for p in paths:
                selected_files.append(p)
                files_listbox.insert("end", os.path.basename(p))

        btn_row = tk.Frame(card, bg=COLOR_SURFACE)
        btn_row.pack(fill="x", pady=8)

        tk.Button(btn_row, text="+ Select Images", bg=COLOR_SURFACE_VARIANT, fg=COLOR_TEXT, relief="flat", command=add_images, padx=10, pady=4).pack(side="left", padx=4)

        def clear_images():
            selected_files.clear()
            files_listbox.delete(0, "end")

        tk.Button(btn_row, text="Clear List", bg=COLOR_SURFACE_VARIANT, fg=COLOR_TEXT_SECONDARY, relief="flat", command=clear_images, padx=8, pady=4).pack(side="left", padx=4)

        tk.Label(card, text="PDF Document Title:", bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(anchor="w", pady=(12, 2))
        title_entry = tk.Entry(card, width=32, font=("Segoe UI", 10))
        title_entry.pack(anchor="w", pady=(0, 12))
        title_entry.insert(0, "Scanned Document")

        def convert_and_save():
            if not selected_files:
                messagebox.showwarning("No Images", "Please select at least one image to convert.")
                return
            out_pdf = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Documents", "*.pdf")])
            if not out_pdf:
                return
            DesktopVaultManager.convert_images_to_pdf(selected_files, out_pdf)

            # Also create as Document entry in Documents Vault
            title = title_entry.get().strip() or "Converted PDF"
            doc = DocumentItem(
                id=str(uuid.uuid4()),
                title=title,
                pages=[DocumentPage(page_id=str(uuid.uuid4()), page_number=i + 1, title_hint=os.path.basename(p)) for i, p in enumerate(selected_files)],
            )
            self.vault.save_document(doc)

            messagebox.showinfo("Success", f"PDF successfully created and saved to Documents Vault!\nSaved to: {out_pdf}")
            clear_images()

        tk.Button(card, text="Generate PDF & Save to Vault", font=("Segoe UI", 10, "bold"), bg=COLOR_PRIMARY, fg=COLOR_TEXT, relief="flat", command=convert_and_save, padx=14, pady=8).pack(anchor="w", pady=10)

    # --- TAB: SHARE CENTER ---
    def show_shares_tab(self) -> None:
        self._clear_main_content()

        header = tk.Frame(self.main_content, bg=COLOR_BG)
        header.pack(fill="x", pady=(0, 16))

        tk.Label(header, text="Secure Share Center", font=("Segoe UI", 16, "bold"), fg=COLOR_TEXT, bg=COLOR_BG).pack(side="left")

        items_frame = tk.Frame(self.main_content, bg=COLOR_BG)
        items_frame.pack(fill="both", expand=True)

        if not self.vault.active_shares:
            tk.Label(items_frame, text="No active shares. Click 'Share' on any Password, Document, or Note to generate a zero-knowledge encrypted link.", fg=COLOR_TEXT_SECONDARY, bg=COLOR_BG).pack(pady=40)
            return

        for share in self.vault.active_shares:
            s_card = tk.Frame(items_frame, bg=COLOR_SURFACE, padx=16, pady=12)
            s_card.pack(fill="x", pady=6)

            info = tk.Frame(s_card, bg=COLOR_SURFACE)
            info.pack(side="left", fill="x", expand=True)

            tk.Label(info, text=share.get("title", "Encrypted Share"), font=("Segoe UI", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_SURFACE).pack(anchor="w")
            tk.Label(info, text=f"Share ID: {share.get('share_id')}", font=("Segoe UI", 8), fg=COLOR_TEXT_SECONDARY, bg=COLOR_SURFACE).pack(anchor="w")

            actions = tk.Frame(s_card, bg=COLOR_SURFACE)
            actions.pack(side="right")

            tk.Button(
                actions,
                text="Revoke Share",
                font=("Segoe UI", 8, "bold"),
                bg=COLOR_SURFACE_VARIANT,
                fg=COLOR_ERROR,
                relief="flat",
                command=lambda sid=share.get("share_id"): self._revoke_share(sid),
                padx=8,
                pady=4,
            ).pack(side="left", padx=4)

    def _revoke_share(self, sid: str) -> None:
        self.vault.revoke_share(sid)
        self.show_shares_tab()

    def _share_item(self, payload: Dict[str, Any]) -> None:
        link = self.vault.create_zero_knowledge_share(payload)
        self._copy_with_auto_clear(link, "Zero-Knowledge Share Link")

    # --- TAB: SETTINGS ---
    def show_settings_tab(self) -> None:
        self._clear_main_content()

        tk.Label(self.main_content, text="Settings & Security", font=("Segoe UI", 16, "bold"), fg=COLOR_TEXT, bg=COLOR_BG).pack(anchor="w", pady=(0, 16))

        card = tk.Frame(self.main_content, bg=COLOR_SURFACE, padx=20, pady=20)
        card.pack(fill="x", pady=8)

        tk.Label(card, text="Daily 4–6 Digit PIN", font=("Segoe UI", 11, "bold"), bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(anchor="w")
        tk.Label(card, text="Quick daily unlock protected with device-local hardware wrapping.", font=("Segoe UI", 9), bg=COLOR_SURFACE, fg=COLOR_TEXT_SECONDARY).pack(anchor="w", pady=(2, 8))

        def setup_pin():
            dlg = tk.Toplevel(self.root)
            dlg.title("Configure 4–6 Digit PIN")
            dlg.geometry("320x200")
            dlg.configure(bg=COLOR_SURFACE, padx=20, pady=20)
            dlg.transient(self.root)
            dlg.grab_set()

            tk.Label(dlg, text="Enter New 4–6 Digit PIN:", bg=COLOR_SURFACE, fg=COLOR_TEXT).pack(pady=4)
            p1 = tk.Entry(dlg, show="•", font=("Segoe UI", 12), justify="center", width=10)
            p1.pack(pady=4)

            def confirm():
                pin = p1.get().strip()
                try:
                    self.vault.setup_pin(pin)
                    messagebox.showinfo("PIN Set", "4–6 Digit PIN successfully set up on this device!")
                    dlg.destroy()
                except Exception as e:
                    messagebox.showerror("PIN Error", str(e))

            tk.Button(dlg, text="Save PIN", bg=COLOR_PRIMARY, fg=COLOR_TEXT, relief="flat", command=confirm, pady=4).pack(pady=10)

        tk.Button(card, text="Set / Change PIN", bg=COLOR_SURFACE_VARIANT, fg=COLOR_ACCENT, relief="flat", command=setup_pin, padx=10, pady=4).pack(anchor="w")


def run_desktop_gui():
    root = tk.Tk()
    data_dir = os.path.join(os.path.expanduser("~"), ".securevault_desktop")
    manager = DesktopVaultManager(data_dir)
    app = SecureVaultAppGUI(root, manager)
    root.mainloop()


if __name__ == "__main__":
    run_desktop_gui()
