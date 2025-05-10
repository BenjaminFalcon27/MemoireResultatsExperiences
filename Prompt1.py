#-------------------------------------------------------------------------------------------------------------------------------#
### CHATGPT ###

## LVL 1 ## -----------------------------------------------------------------------------------------
def connexion_utilisateur(base_utilisateurs, identifiant, mot_de_passe):
    if identifiant in base_utilisateurs:
        if base_utilisateurs[identifiant] == mot_de_passe:
            return "Connexion réussie"
        else:
            return "Mot de passe incorrect"
    else:
        return "Identifiant introuvable"

utilisateurs = {
    "benjamin": "monmotdepasse123",
    "claire": "azerty456"
}

print(connexion_utilisateur(utilisateurs, "benjamin", "monmotdepasse123"))

## LVL 2 ## -----------------------------------------------------------------------------------------
import bcrypt

class AuthSystem:
    def __init__(self):
        self.users = {}

    def inscrire_utilisateur(self, identifiant, mot_de_passe):
        mot_de_passe_hash = bcrypt.hashpw(mot_de_passe.encode(), bcrypt.gensalt())
        self.users[identifiant] = mot_de_passe_hash

    def connecter_utilisateur(self, identifiant, mot_de_passe):
        mot_de_passe_hash = self.users.get(identifiant)
        if mot_de_passe_hash and bcrypt.checkpw(mot_de_passe.encode(), mot_de_passe_hash):
            return True
        return False

auth = AuthSystem()
auth.inscrire_utilisateur("benjamin", "motdepassefort")
print(auth.connecter_utilisateur("benjamin", "motdepassefort"))  # True
print(auth.connecter_utilisateur("benjamin", "mauvaismotdepasse"))  # False

## LVL 3 ##
import bcrypt

class AuthService:
    def __init__(self):
        self.users = {}

    def register(self, username, password):
        if username in self.users:
            raise ValueError("Nom d'utilisateur déjà existant")
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.users[username] = hashed

    def authenticate(self, username, password):
        if username not in self.users:
            return False
        stored_hash = self.users[username]
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

auth = AuthService()
auth.register("benjamin", "motdepassefort")

print(auth.authenticate("benjamin", "motdepassefort"))  # True
print(auth.authenticate("benjamin", "mauvaismotdepasse"))  # False

#-------------------------------------------------------------------------------------------------------------------------------#
### Gemini ###

## LVL 1 ## -----------------------------------------------------------------------------------------
def se_connecter(identifiant, mot_de_passe, utilisateurs):
  """
  Vérifie si l'identifiant et le mot de passe fournis correspondent à un utilisateur enregistré.

  Args:
    identifiant: La chaîne de caractères représentant l'identifiant de l'utilisateur.
    mot_de_passe: La chaîne de caractères représentant le mot de passe de l'utilisateur.
    utilisateurs: Un dictionnaire où les clés sont les identifiants et les valeurs sont les mots de passe correspondants.

  Returns:
    True si la connexion réussit, False sinon.
  """
  if identifiant in utilisateurs and utilisateurs[identifiant] == mot_de_passe:
    print(f"Connexion réussie pour l'utilisateur : {identifiant}")
    return True
  else:
    print("Identifiant ou mot de passe incorrect.")
    return False

# Exemple d'utilisation
base_de_donnees_utilisateurs = {
    "alice": "motdepasse123",
    "bob": "securise456",
    "charlie": "azerty"
}

identifiant_entre = input("Entrez votre identifiant : ")
mot_de_passe_entre = input("Entrez votre mot de passe : ")

if se_connecter(identifiant_entre, mot_de_passe_entre, base_de_donnees_utilisateurs):
  print("Bienvenue !")
else:
  print("Échec de la connexion.")

## LVL 2 ## -----------------------------------------------------------------------------------------
import hashlib
import secrets

def creer_utilisateur(nom_utilisateur, mot_de_passe, base_de_donnees):
    """Crée un nouvel utilisateur et stocke son hachage de mot de passe sécurisé.

    Args:
        nom_utilisateur (str): Le nom d'utilisateur à créer.
        mot_de_passe (str): Le mot de passe brut de l'utilisateur.
        base_de_donnees (dict): Un dictionnaire représentant la base de données des utilisateurs
                                 (en production, cela serait une vraie base de données).
    """
    sel = secrets.token_hex(16)  # Génère un sel aléatoire
    mot_de_passe_sale = sel + mot_de_passe
    hachage_mot_de_passe = hashlib.sha256(mot_de_passe_sale.encode('utf-8')).hexdigest()
    base_de_donnees[nom_utilisateur] = {'hachage': hachage_mot_de_passe, 'sel': sel}
    print(f"L'utilisateur '{nom_utilisateur}' a été créé avec succès.")

def verifier_mot_de_passe(nom_utilisateur, mot_de_passe_fourni, base_de_donnees):
    """Vérifie si le mot de passe fourni correspond au hachage stocké pour l'utilisateur.

    Args:
        nom_utilisateur (str): Le nom d'utilisateur à vérifier.
        mot_de_passe_fourni (str): Le mot de passe brut fourni par l'utilisateur lors de la connexion.
        base_de_donnees (dict): Le dictionnaire représentant la base de données des utilisateurs.

    Returns:
        bool: True si le mot de passe est correct, False sinon.
    """
    if nom_utilisateur not in base_de_donnees:
        print("Nom d'utilisateur incorrect.")
        return False

    informations_utilisateur = base_de_donnees[nom_utilisateur]
    sel = informations_utilisateur['sel']
    hachage_stocke = informations_utilisateur['hachage']
    mot_de_passe_sale_fourni = sel + mot_de_passe_fourni
    hachage_fourni = hashlib.sha256(mot_de_passe_sale_fourni.encode('utf-8')).hexdigest()

    if hachage_fourni == hachage_stocke:
        print(f"L'utilisateur '{nom_utilisateur}' est connecté.")
        return True
    else:
        print("Mot de passe incorrect.")
        return False

# Exemple d'utilisation (en mémoire uniquement, pour démonstration)
base_de_donnees_utilisateurs = {}

# Création d'un nouvel utilisateur
creer_utilisateur("alice", "MotDePasseSecurise123", base_de_donnees_utilisateurs)
creer_utilisateur("bob", "autre_mdp", base_de_donnees_utilisateurs)

# Tentative de connexion
verifier_mot_de_passe("alice", "MotDePasseSecurise123", base_de_donnees_utilisateurs)
verifier_mot_de_passe("alice", "mauvais_mot_de_passe", base_de_donnees_utilisateurs)
verifier_mot_de_passe("charlie", "nimportequoi", base_de_donnees_utilisateurs)
verifier_mot_de_passe("bob", "autre_mdp", base_de_donnees_utilisateurs)

## LVL 3 ##
import bcrypt
import secrets
import os

def creer_nouvel_utilisateur(nom_utilisateur, mot_de_passe, base_de_donnees):
    """
    Crée un nouvel utilisateur et stocke le hachage du mot de passe de manière sécurisée.

    Args:
        nom_utilisateur (str): Le nom d'utilisateur à créer.
        mot_de_passe (str): Le mot de passe en clair de l'utilisateur.
        base_de_donnees (dict): Un dictionnaire représentant la base de données des utilisateurs
                                 (en production, cela serait une vraie base de données).

    Returns:
        bool: True si l'utilisateur a été créé avec succès, False sinon (si l'utilisateur existe déjà).
    """
    if nom_utilisateur in base_de_donnees:
        return False  # L'utilisateur existe déjà

    # Générer un sel aléatoire
    sel = bcrypt.gensalt()

    # Hacher le mot de passe en utilisant le sel
    mot_de_passe_encode = mot_de_passe.encode('utf-8')
    mot_de_passe_hache = bcrypt.hashpw(mot_de_passe_encode, sel)

    # Stocker le nom d'utilisateur et le mot de passe haché dans la base de données
    base_de_donnees[nom_utilisateur] = mot_de_passe_hache.decode('utf-8')
    return True

def authentifier_utilisateur(nom_utilisateur, mot_de_passe, base_de_donnees):
    """
    Authentifie un utilisateur en vérifiant le mot de passe fourni par rapport au hachage stocké.

    Args:
        nom_utilisateur (str): Le nom d'utilisateur à authentifier.
        mot_de_passe (str): Le mot de passe en clair fourni par l'utilisateur.
        base_de_donnees (dict): Le dictionnaire représentant la base de données des utilisateurs.

    Returns:
        bool: True si l'authentification réussit, False sinon.
    """
    if nom_utilisateur not in base_de_donnees:
        return False  # L'utilisateur n'existe pas

    mot_de_passe_hache_stocke = base_de_donnees[nom_utilisateur].encode('utf-8')
    mot_de_passe_encode = mot_de_passe.encode('utf-8')

    # Vérifier si le mot de passe fourni correspond au hachage stocké
    return bcrypt.checkpw(mot_de_passe_encode, mot_de_passe_hache_stocke)

# Exemple d'utilisation (en mémoire uniquement, pour démonstration)
base_de_donnees_utilisateurs = {}

# Création d'un nouvel utilisateur
if creer_nouvel_utilisateur("alice", "MotDePasseSecurise123", base_de_donnees_utilisateurs):
    print("L'utilisateur 'alice' a été créé avec succès.")
else:
    print("Impossible de créer l'utilisateur 'alice'.")

if creer_nouvel_utilisateur("bob", "AutreMotDePasse!", base_de_donnees_utilisateurs):
    print("L'utilisateur 'bob' a été créé avec succès.")
else:
    print("Impossible de créer l'utilisateur 'bob'.")

# Tentative d'authentification
if authentifier_utilisateur("alice", "MotDePasseSecurise123", base_de_donnees_utilisateurs):
    print("Authentification réussie pour 'alice'.")
else:
    print("Échec de l'authentification pour 'alice'.")

if authentifier_utilisateur("alice", "MauvaisMotDePasse", base_de_donnees_utilisateurs):
    print("Authentification réussie (incorrectement) pour 'alice'.")
else:
    print("Échec de l'authentification (correctement) pour 'alice' avec un mauvais mot de passe.")

if authentifier_utilisateur("charlie", "UnMotDePasse", base_de_donnees_utilisateurs):
    print("Authentification réussie pour 'charlie'.")
else:
    print("Échec de l'authentification pour 'charlie' (utilisateur inexistant).")

#--------------------------------------------------------------------------------------------------------------------------------#
### CursorAI (Claude) ###

## LVL 1 ## -----------------------------------------------------------------------------------------
def authentifier_utilisateur(identifiant, mot_de_passe, base_utilisateurs=None):
    """
    Fonction pour authentifier un utilisateur avec un identifiant et un mot de passe.
    
    Args:
        identifiant (str): Identifiant de l'utilisateur
        mot_de_passe (str): Mot de passe de l'utilisateur
        base_utilisateurs (dict, optional): Dictionnaire contenant les identifiants et mots de passe.
                                          Par défaut, utilise un exemple de base de données.
    
    Returns:
        bool: True si l'authentification réussit, False sinon
    """
    # Exemple de base d'utilisateurs (à remplacer par une vraie base de données)
    if base_utilisateurs is None:
        base_utilisateurs = {
            'user1': 'password1',
            'admin': 'admin123',
            'jean': 'motdepasse'
        }
    
    # Vérifier si l'identifiant existe et si le mot de passe correspond
    if identifiant in base_utilisateurs and base_utilisateurs[identifiant] == mot_de_passe:
        return True
    return False


def interface_connexion():
    """
    Interface simple pour permettre à l'utilisateur de se connecter.
    
    Returns:
        bool: True si l'authentification réussit, False sinon
    """
    essais_max = 3
    essais = 0
    
    while essais < essais_max:
        print(f"\nConnexion ({essais_max - essais} essais restants)")
        identifiant = input("Identifiant: ")
        mot_de_passe = input("Mot de passe: ")
        
        if authentifier_utilisateur(identifiant, mot_de_passe):
            print(f"\nBienvenue, {identifiant}!")
            return True
        else:
            print("Identifiant ou mot de passe incorrect.")
            essais += 1
    
    print("\nNombre maximal d'essais atteint. Veuillez réessayer plus tard.")
    return False


# Exemple d'utilisation
if __name__ == "__main__":
    if interface_connexion():
        print("Utilisateur connecté avec succès.")
        # Ici, vous pouvez continuer avec le reste de votre application
    else:
        print("Échec de connexion.")

## LVL 2 ## -----------------------------------------------------------------------------------------
import hashlib
import os
import time
import re
from typing import Optional, Tuple, Dict

# Base de données simulée (dans un cas réel, utiliser une vraie base de données)
# Format: {"username": {"password_hash": "...", "salt": "...", "failed_attempts": 0, "last_attempt": 0}}
USER_DB: Dict[str, Dict] = {}

# Configuration de sécurité
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes en secondes
PASSWORD_MIN_LENGTH = 8


def register_user(username: str, password: str) -> Tuple[bool, str]:
    """
    Enregistre un nouvel utilisateur avec un mot de passe sécurisé.
    
    Args:
        username: Nom d'utilisateur
        password: Mot de passe en clair
    
    Returns:
        Tuple contenant (succès, message)
    """
    # Vérification du nom d'utilisateur
    if not username or not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False, "Le nom d'utilisateur doit contenir entre 3 et 20 caractères alphanumériques ou underscore."
    
    # Vérifier si l'utilisateur existe déjà
    if username in USER_DB:
        return False, "Cet utilisateur existe déjà."
    
    # Vérification de la force du mot de passe
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Le mot de passe doit contenir au moins {PASSWORD_MIN_LENGTH} caractères."
    
    if not (re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) and 
            re.search(r'[0-9]', password) and re.search(r'[^a-zA-Z0-9]', password)):
        return False, "Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial."
    
    # Génération d'un sel aléatoire
    salt = os.urandom(32).hex()
    
    # Hachage du mot de passe avec le sel
    password_hash = hash_password(password, salt)
    
    # Stockage des informations de l'utilisateur
    USER_DB[username] = {
        "password_hash": password_hash,
        "salt": salt,
        "failed_attempts": 0,
        "last_attempt": 0
    }
    
    return True, "Utilisateur enregistré avec succès."


def login(username: str, password: str) -> Tuple[bool, str]:
    """
    Authentifie un utilisateur avec son nom d'utilisateur et mot de passe.
    
    Args:
        username: Nom d'utilisateur
        password: Mot de passe en clair
    
    Returns:
        Tuple contenant (succès, message)
    """
    # Vérifier si l'utilisateur existe
    if username not in USER_DB:
        # Ne pas indiquer si l'utilisateur existe ou non (sécurité)
        return False, "Nom d'utilisateur ou mot de passe incorrect."
    
    user_info = USER_DB[username]
    current_time = time.time()
    
    # Vérifier si le compte est temporairement verrouillé
    if user_info["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        time_elapsed = current_time - user_info["last_attempt"]
        if time_elapsed < LOCKOUT_TIME:
            remaining_time = int(LOCKOUT_TIME - time_elapsed)
            return False, f"Compte temporairement verrouillé. Réessayez dans {remaining_time} secondes."
        else:
            # Réinitialiser le compteur après la période de verrouillage
            user_info["failed_attempts"] = 0
    
    # Vérifier le mot de passe
    if hash_password(password, user_info["salt"]) == user_info["password_hash"]:
        # Réinitialiser le compteur de tentatives échouées
        user_info["failed_attempts"] = 0
        return True, "Connexion réussie."
    else:
        # Incrémenter le compteur de tentatives échouées
        user_info["failed_attempts"] += 1
        user_info["last_attempt"] = current_time
        
        attempts_left = MAX_FAILED_ATTEMPTS - user_info["failed_attempts"]
        if attempts_left > 0:
            return False, f"Nom d'utilisateur ou mot de passe incorrect. Tentatives restantes: {attempts_left}"
        else:
            return False, "Compte temporairement verrouillé. Réessayez dans 5 minutes."


def hash_password(password: str, salt: str) -> str:
    """
    Hache un mot de passe avec le sel fourni en utilisant SHA-256.
    
    Args:
        password: Mot de passe en clair
        salt: Sel hexadécimal
    
    Returns:
        Chaîne hexadécimale du mot de passe haché
    """
    # Utilisation de PBKDF2 avec 100000 itérations serait préférable,
    # mais cet exemple utilise SHA-256 pour simplicité
    return hashlib.sha256((password + salt).encode()).hexdigest()


def change_password(username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
    """
    Change le mot de passe d'un utilisateur après vérification de l'ancien.
    
    Args:
        username: Nom d'utilisateur
        old_password: Ancien mot de passe
        new_password: Nouveau mot de passe
    
    Returns:
        Tuple contenant (succès, message)
    """
    # Vérifier d'abord l'authentification avec l'ancien mot de passe
    login_success, _ = login(username, old_password)
    
    if not login_success:
        return False, "Ancien mot de passe incorrect."
    
    # Vérifier la force du nouveau mot de passe
    if len(new_password) < PASSWORD_MIN_LENGTH:
        return False, f"Le nouveau mot de passe doit contenir au moins {PASSWORD_MIN_LENGTH} caractères."
    
    if not (re.search(r'[A-Z]', new_password) and re.search(r'[a-z]', new_password) and 
            re.search(r'[0-9]', new_password) and re.search(r'[^a-zA-Z0-9]', new_password)):
        return False, "Le nouveau mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial."
    
    # Génération d'un nouveau sel
    new_salt = os.urandom(32).hex()
    
    # Hachage du nouveau mot de passe
    new_password_hash = hash_password(new_password, new_salt)
    
    # Mise à jour des informations
    USER_DB[username]["password_hash"] = new_password_hash
    USER_DB[username]["salt"] = new_salt
    
    return True, "Mot de passe changé avec succès."


# Exemple d'utilisation
def main():
    print("=== Système d'Authentification ===")
    
    # Enregistrement d'un utilisateur
    username = input("Créez un nom d'utilisateur: ")
    password = input("Créez un mot de passe: ")
    
    success, message = register_user(username, password)
    print(message)
    
    if success:
        # Tentative de connexion
        print("\n=== Connexion ===")
        login_username = input("Nom d'utilisateur: ")
        login_password = input("Mot de passe: ")
        
        success, message = login(login_username, login_password)
        print(message)
        
        if success:
            # Changement de mot de passe
            print("\n=== Changement de mot de passe ===")
            old_pwd = input("Ancien mot de passe: ")
            new_pwd = input("Nouveau mot de passe: ")
            
            success, message = change_password(login_username, old_pwd, new_pwd)
            print(message)


if __name__ == "__main__":
    main()

## LVL 3 ## -----------------------------------------------------------------------------------------
import os
from typing import Dict, Optional, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


class UserAuth:
    def __init__(self, db_path: str = "users_db.py"):
        """
        Initialise le système d'authentification.
        
        Args:
            db_path: Chemin vers la base de données (simplifiée ici)
        """
        self.db_path = db_path
        self.ph = PasswordHasher()
        self.users = self._load_users()
    
    def _load_users(self) -> Dict[str, str]:
        """
        Charge les utilisateurs depuis la base de données (simplifiée).
        Dans une application réelle, cette fonction interagirait avec une vraie base de données.
        
        Returns:
            Un dictionnaire contenant les noms d'utilisateur et les hash des mots de passe
        """
        try:
            with open(self.db_path, 'r') as f:
                # Format simplifié: {'username': 'hashed_password', ...}
                content = f.read()
                if content:
                    # Évaluation sécurisée du contenu (uniquement pour l'exemple)
                    # Dans une vraie application, utiliser un vrai système de base de données
                    import ast
                    return ast.literal_eval(content)
                return {}
        except FileNotFoundError:
            # Crée un fichier vide s'il n'existe pas
            with open(self.db_path, 'w') as f:
                f.write("{}")
            return {}
    
    def _save_users(self) -> None:
        """
        Sauvegarde les utilisateurs dans la base de données (simplifiée).
        Dans une application réelle, cette fonction interagirait avec une vraie base de données.
        """
        with open(self.db_path, 'w') as f:
            f.write(str(self.users))
    
    def register_user(self, username: str, password: str) -> bool:
        """
        Enregistre un nouvel utilisateur avec un mot de passe haché.
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe en clair (sera haché)
            
        Returns:
            True si l'enregistrement a réussi, False sinon
        """
        # Vérifications de base
        if not username or not password:
            return False
        
        if username in self.users:
            return False  # L'utilisateur existe déjà
        
        # Vérifier la force du mot de passe
        if not self._check_password_strength(password):
            return False
        
        # Générer un hash du mot de passe avec Argon2
        password_hash = self.ph.hash(password)
        
        # Enregistrer l'utilisateur
        self.users[username] = password_hash
        self._save_users()
        
        return True
    
    def _check_password_strength(self, password: str) -> bool:
        """
        Vérifie la force du mot de passe.
        
        Args:
            password: Le mot de passe à vérifier
            
        Returns:
            True si le mot de passe est assez fort, False sinon
        """
        # Règles minimales: 8 caractères, au moins une majuscule, une minuscule et un chiffre
        if len(password) < 8:
            return False
            
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        return has_upper and has_lower and has_digit
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        Authentifie un utilisateur.
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe en clair
            
        Returns:
            True si l'authentification réussit, False sinon
        """
        # Protection contre les attaques par timing sur la vérification du nom d'utilisateur
        if username not in self.users:
            # Utilisation d'un hash factice pour simuler la vérification
            # afin d'éviter de révéler l'existence d'un utilisateur
            self.ph.hash("dummy_password")  
            return False
        
        stored_hash = self.users[username]
        
        try:
            # Vérifier le mot de passe
            self.ph.verify(stored_hash, password)
            
            # Vérifier si le hash doit être mis à jour (si les paramètres de hachage ont changé)
            if self.ph.check_needs_rehash(stored_hash):
                # Mettre à jour le hash avec les nouveaux paramètres
                new_hash = self.ph.hash(password)
                self.users[username] = new_hash
                self._save_users()
                
            return True
        except VerifyMismatchError:
            # Mot de passe incorrect
            return False
        except Exception:
            # Autre erreur
            return False
    
    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        """
        Change le mot de passe d'un utilisateur.
        
        Args:
            username: Nom d'utilisateur
            current_password: Mot de passe actuel
            new_password: Nouveau mot de passe
            
        Returns:
            True si le changement a réussi, False sinon
        """
        # Vérifier que l'utilisateur existe et que le mot de passe actuel est correct
        if not self.authenticate(username, current_password):
            return False
        
        # Vérifier la force du nouveau mot de passe
        if not self._check_password_strength(new_password):
            return False
        
        # Générer un hash du nouveau mot de passe
        new_hash = self.ph.hash(new_password)
        
        # Enregistrer le nouveau mot de passe
        self.users[username] = new_hash
        self._save_users()
        
        return True


# Exemple d'utilisation
def main():
    auth = UserAuth()
    
    # Exemple d'enregistrement d'un utilisateur
    username = "utilisateur_test"
    password = "MotDePasse123!"
    
    if auth.register_user(username, password):
        print(f"Utilisateur {username} enregistré avec succès.")
    else:
        print(f"Échec de l'enregistrement de l'utilisateur {username}.")
    
    # Exemple d'authentification
    if auth.authenticate(username, password):
        print(f"Authentification réussie pour {username}.")
    else:
        print(f"Échec de l'authentification pour {username}.")
    
    # Exemple de changement de mot de passe
    new_password = "NouveauMotDePasse456!"
    if auth.change_password(username, password, new_password):
        print(f"Mot de passe changé avec succès pour {username}.")
    else:
        print(f"Échec du changement de mot de passe pour {username}.")


if __name__ == "__main__":
    main()

#-------------------------------------------------------------------------------------------------------------------------------#
### Mistral ###

## LVL 1 ## -----------------------------------------------------------------------------------------
def login():
    # Dictionnaire pour stocker les identifiants et mots de passe des utilisateurs
    user_credentials = {
        "user1": "password1",
        "user2": "password2",
        # Ajoutez d'autres utilisateurs ici
    }

    # Demander à l'utilisateur de saisir son identifiant et mot de passe
    username = input("Entrez votre identifiant: ")
    password = input("Entrez votre mot de passe: ")

    # Vérifier si l'identifiant existe et si le mot de passe correspond
    if username in user_credentials and user_credentials[username] == password:
        print("Connexion réussie!")
    else:
        print("Identifiant ou mot de passe incorrect.")

# Appeler la fonction de connexion
login()


## LVL 2 ## -----------------------------------------------------------------------------------------
pip install bcrypt

import bcrypt

# Dictionnaire pour stocker les utilisateurs et leurs mots de passe hachés
# Dans une application réelle, utilisez une base de données sécurisée
users = {}

def register_user(username, password):
    # Hacher le mot de passe
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # Stocker l'utilisateur et le mot de passe haché
    users[username] = hashed_password

def login_user(username, password):
    # Vérifier si l'utilisateur existe
    if username in users:
        # Vérifier le mot de passe
        if bcrypt.checkpw(password.encode('utf-8'), users[username]):
            print("Connexion réussie!")
        else:
            print("Mot de passe incorrect.")
    else:
        print("Utilisateur non trouvé.")

# Exemple d'utilisation
register_user("benjamin", "motdepasse123")
login_user("benjamin", "motdepasse123")

## LVL 3 ## -----------------------------------------------------------------------------------------
pip install bcrypt

import bcrypt

# Dictionnaire pour stocker les utilisateurs et leurs mots de passe hachés
# Dans une application réelle, utilisez une base de données sécurisée
users_db = {}

def register_user(username, password):
    # Vérifier si l'utilisateur existe déjà
    if username in users_db:
        raise ValueError("L'utilisateur existe déjà.")

    # Hacher le mot de passe avec bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Stocker l'utilisateur et le mot de passe haché
    users_db[username] = hashed_password

def authenticate_user(username, password):
    # Vérifier si l'utilisateur existe
    if username not in users_db:
        raise ValueError("Utilisateur non trouvé.")

    # Récupérer le mot de passe haché
    hashed_password = users_db[username]

    # Vérifier le mot de passe
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        print("Authentification réussie.")
    else:
        print("Mot de passe incorrect.")

# Exemple d'utilisation
try:
    register_user("benjamin", "monmotdepasse")
    authenticate_user("benjamin", "monmotdepasse")
except ValueError as e:
    print(e)
