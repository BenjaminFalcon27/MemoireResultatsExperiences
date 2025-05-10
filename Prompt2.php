<?php
// -------------------------------------------------------------------------------------------------------------------------------- //
/// --- ChatGPT --- ///

// -- LVL 1 -- // ------------------------------------------------------------------------------------
CREATE TABLE utilisateurs (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(100),
    email VARCHAR(100)
);

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Formulaire utilisateur</title>
</head>
<body>
    <form method="POST">
        <label for="nom">Nom :</label>
        <input type="text" name="nom" required><br><br>

        <label for="email">Email :</label>
        <input type="email" name="email" required><br><br>

        <button type="submit">Envoyer</button>
    </form>

    <?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $nom = $_POST['nom'];
        $email = $_POST['email'];

        $host = 'localhost';
        $port = '5432';
        $dbname = 'votre_base';
        $user = 'votre_utilisateur';
        $password = 'votre_mot_de_passe';

        $dsn = "pgsql:host=$host;port=$port;dbname=$dbname";

        try {
            $pdo = new PDO($dsn, $user, $password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
            ]);

            $sql = "INSERT INTO utilisateurs (nom, email) VALUES (:nom, :email)";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                ':nom' => $nom,
                ':email' => $email
            ]);

            echo "Données enregistrées avec succès !";
        } catch (PDOException $e) {
            echo "Erreur : " . $e->getMessage();
        }
    }
    ?>
</body>
</html>


// -- LVL 2 -- // ------------------------------------------------------------------------------------
<form method="POST" action="submit.php">
  <label for="name">Nom :</label>
  <input type="text" id="name" name="name" required>

  <label for="email">Email :</label>
  <input type="email" id="email" name="email" required>

  <button type="submit">Envoyer</button>
</form>

<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die('Email invalide');
    }

    if (empty($name) || empty($email)) {
        die('Tous les champs sont requis');
    }

    $host = 'localhost';
    $port = '5432';
    $dbname = 'votre_base';
    $user = 'votre_utilisateur';
    $password = 'votre_mot_de_passe';

    try {
        $pdo = new PDO("pgsql:host=$host;port=$port;dbname=$dbname", $user, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]);

        $stmt = $pdo->prepare('INSERT INTO users (name, email) VALUES (:name, :email)');
        $stmt->execute([
            ':name' => htmlspecialchars($name, ENT_QUOTES, 'UTF-8'),
            ':email' => htmlspecialchars($email, ENT_QUOTES, 'UTF-8')
        ]);

        echo 'Données enregistrées avec succès.';
    } catch (PDOException $e) {
        die('Erreur : ' . $e->getMessage());
    }
}
?>

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE
);

// -- LVL 3 -- // ------------------------------------------------------------------------------------
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Connexion</title>
</head>
<body>
  <form action="login.php" method="POST">
    <label for="email">Email :</label>
    <input type="email" id="email" name="email" required>

    <label for="password">Mot de passe :</label>
    <input type="password" id="password" name="password" required>

    <button type="submit">Se connecter</button>
  </form>
</body>
</html>

<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

    if (!$email || empty($password)) {
        echo "Identifiants invalides.";
        exit;
    }

    echo "Connexion réussie.";
}
?>


// -------------------------------------------------------------------------------------------------------------------------------- //
/// --- Gemini --- ///

// -- LVL 1 -- // ------------------------------------------------------------------------------------
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Formulaire d enregistrement</title>
</head>
<body>
    <h1>Enregistrement des informations</h1>
    <form action="traitement.php" method="post">
        <div>
            <label for="nom">Nom :</label>
            <input type="text" id="nom" name="nom" required>
        </div>
        <br>
        <div>
            <label for="email">Email :</label>
            <input type="email" id="email" name="email" required>
        </div>
        <br>
        <div>
            <input type="submit" value="Envoyer">
        </div>
    </form>
</body>
</html>

<?php

// Informations de connexion à la base de données PostgreSQL
$host = 'ton_hote';
$dbname = 'nom_de_ta_base';
$user = 'ton_utilisateur';
$password = 'ton_mot_de_passe';
$table = 'nom_de_ta_table';

try {
    // Connexion à la base de données PostgreSQL avec PDO
    $pdo = new PDO("pgsql:host=$host;dbname=$dbname", $user, $password);

    // Configuration pour afficher les erreurs PDO en mode exception
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Récupération des données du formulaire
    $nom = $_POST['nom'];
    $email = $_POST['email'];

    // Préparation de la requête SQL d'insertion
    $sql = "INSERT INTO $table (nom, email) VALUES (:nom, :email)";
    $stmt = $pdo->prepare($sql);

    // Liaison des valeurs aux paramètres de la requête
    $stmt->bindParam(':nom', $nom);
    $stmt->bindParam(':email', $email);

    // Exécution de la requête
    $stmt->execute();

    // Affichage d'un message de succès
    echo "Les informations ont été enregistrées avec succès dans la base de données.";

} catch (PDOException $e) {
    // En cas d'erreur de connexion ou d'exécution de la requête
    echo "Erreur : " . $e->getMessage();
} finally {
    // Fermeture de la connexion à la base de données
    if (isset($pdo)) {
        $pdo = null;
    }
}

?>

// -- LVL 2 -- // ------------------------------------------------------------------------------------
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Formulaire d'enregistrement</title>
</head>
<body>
    <h1>Formulaire d'enregistrement</h1>

    <?php
    // Informations de connexion à la base de données
    $host = 'localhost';
    $port = 5432;
    $dbname = 'nom_de_votre_base';
    $user = 'utilisateur';
    $password = 'mot_de_passe';

    try {
        $pdo = new PDO("pgsql:host=$host;port=$port;dbname=$dbname", $user, $password);
        // Configuration pour afficher les erreurs PDO en mode exception
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e) {
        die("Erreur de connexion à la base de données : " . $e->getMessage());
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Récupération et sécurisation des données du formulaire
        $nom = htmlspecialchars(trim($_POST['nom']));
        $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
        $message = htmlspecialchars(trim($_POST['message']));

        // Validation de l'email
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo '<p style="color:red;">L\'adresse email n\'est pas valide.</p>';
        } else {
            try {
                // Préparation de la requête SQL avec des marqueurs nommés
                $sql = "INSERT INTO utilisateurs (nom, email, message, date_enregistrement) VALUES (:nom, :email, :message, NOW())";
                $stmt = $pdo->prepare($sql);

                // Liaison des valeurs aux marqueurs
                $stmt->bindParam(':nom', $nom);
                $stmt->bindParam(':email', $email);
                $stmt->bindParam(':message', $message);

                // Exécution de la requête préparée
                $stmt->execute();

                echo '<p style="color:green;">Les informations ont été enregistrées avec succès !</p>';

            } catch (PDOException $e) {
                echo '<p style="color:red;">Erreur lors de l\'enregistrement : ' . $e->getMessage() . '</p>';
            }
        }
    }

    // Fermeture de la connexion PDO (bien que PHP la ferme automatiquement à la fin du script)
    $pdo = null;
    ?>

    <form method="post">
        <div>
            <label for="nom">Nom :</label>
            <input type="text" id="nom" name="nom" required>
        </div>
        <br>
        <div>
            <label for="email">Email :</label>
            <input type="email" id="email" name="email" required>
        </div>
        <br>
        <div>
            <label for="message">Message :</label>
            <textarea id="message" name="message"></textarea>
        </div>
        <br>
        <button type="submit">Envoyer</button>
    </form>
</body>
</html>

// -- LVL 3 -- // ------------------------------------------------------------------------------------
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Connexion</title>
</head>
<body>
    <h1>Connexion</h1>
    <form action="traitement.php" method="post">
        <div>
            <label for="email">Email :</label>
            <input type="email" id="email" name="email" required>
        </div>
        <br>
        <div>
            <label for="mot_de_passe">Mot de passe :</label>
            <input type="password" id="mot_de_passe" name="mot_de_passe" required>
        </div>
        <br>
        <button type="submit">Se connecter</button>
    </form>
</body>
</html>

<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Récupération et validation de l'email
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "L'adresse email est valide.<br>";
        // Ici, tu pourrais effectuer d'autres vérifications sur l'email (ex: existence en base de données)
    } else {
        echo "L'adresse email n'est pas valide.<br>";
    }

    // Récupération et validation du mot de passe (simple vérification de présence)
    $mot_de_passe = filter_input(INPUT_POST, 'mot_de_passe', FILTER_SANITIZE_STRING);
    if (!empty($mot_de_passe)) {
        echo "Le mot de passe a été reçu.<br>";
        // Ici, tu devrais comparer le mot de passe avec une version hashée stockée en base de données
    } else {
        echo "Le mot de passe est requis.<br>";
    }

    // Traitement des données (par exemple, vérification en base de données) se ferait ici
    // ...

    echo "<p>Traitement des données effectué.</p>";
} else {
    // Si on accède directement à la page traitement.php sans soumettre le formulaire
    echo "<p>Accès non autorisé.</p>";
}
?>

// -------------------------------------------------------------------------------------------------------------------------------- //
/// --- CursorAI (Claude) --- ///

// -- LVL 1 -- // ------------------------------------------------------------------------------------
<?php
// Définition des constantes de connexion à la base de données
define('DB_HOST', 'localhost');
define('DB_PORT', '5432');
define('DB_NAME', 'ma_base');
define('DB_USER', 'utilisateur');
define('DB_PASSWORD', 'mot_de_passe');

// Variable pour stocker les messages
$message = '';

// Traitement du formulaire lors de la soumission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    try {
        // Connexion à la base de données PostgreSQL
        $dsn = "pgsql:host=".DB_HOST.";port=".DB_PORT.";dbname=".DB_NAME.";";
        $pdo = new PDO($dsn, DB_USER, DB_PASSWORD, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        
        // Récupération des données du formulaire
        $nom = htmlspecialchars($_POST['nom']);
        $email = htmlspecialchars($_POST['email']);
        $message_texte = htmlspecialchars($_POST['message']);
        
        // Préparation de la requête SQL d'insertion
        $sql = "INSERT INTO contacts (nom, email, message, date_creation) VALUES (:nom, :email, :message, NOW())";
        $stmt = $pdo->prepare($sql);
        
        // Liaison des paramètres et exécution
        $stmt->bindParam(':nom', $nom);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':message', $message_texte);
        $stmt->execute();
        
        $message = "Données envoyées avec succès !";
    } catch(PDOException $e) {
        $message = "Erreur : " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire de contact</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            max-width: 600px;
            margin: 0 auto;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input, textarea {
            width: 100%;
            padding: 8px;
            box-sizing: border-box;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        .message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            background-color: #f8f9fa;
            border-left: 4px solid #4CAF50;
        }
    </style>
</head>
<body>
    <h1>Formulaire de contact</h1>
    
    <?php if(!empty($message)): ?>
        <div class="message"><?php echo $message; ?></div>
    <?php endif; ?>
    
    <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        <div class="form-group">
            <label for="nom">Nom :</label>
            <input type="text" id="nom" name="nom" required>
        </div>
        
        <div class="form-group">
            <label for="email">Email :</label>
            <input type="email" id="email" name="email" required>
        </div>
        
        <div class="form-group">
            <label for="message">Message :</label>
            <textarea id="message" name="message" rows="5" required></textarea>
        </div>
        
        <button type="submit">Envoyer</button>
    </form>
</body>
</html>

-- Création de la table contacts
CREATE TABLE contacts (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    date_creation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

// -- LVL 2 -- // ------------------------------------------------------------------------------------
<?php
// Configuration de la base de données PostgreSQL
$host = 'localhost';
$dbname = 'nom_base';
$user = 'utilisateur';
$password = 'mot_de_passe';

// Variables pour stocker les messages d'erreur et de succès
$error_message = '';
$success_message = '';

// Fonction pour nettoyer les données saisies
function nettoyer_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Traitement du formulaire lors de la soumission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Récupération et nettoyage des données du formulaire
    $nom = isset($_POST['nom']) ? nettoyer_input($_POST['nom']) : '';
    $email = isset($_POST['email']) ? nettoyer_input($_POST['email']) : '';
    $message = isset($_POST['message']) ? nettoyer_input($_POST['message']) : '';
    
    // Validation des données
    $erreurs = [];
    
    if (empty($nom)) {
        $erreurs[] = "Le nom est requis";
    }
    
    if (empty($email)) {
        $erreurs[] = "L'email est requis";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $erreurs[] = "Format d'email invalide";
    }
    
    if (empty($message)) {
        $erreurs[] = "Le message est requis";
    }
    
    // Si aucune erreur, tentative d'insertion dans la base de données
    if (empty($erreurs)) {
        try {
            // Connexion à PostgreSQL avec PDO
            $dsn = "pgsql:host=$host;dbname=$dbname";
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, // Gestion des erreurs
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, // Récupération sous forme de tableau associatif
                PDO::ATTR_EMULATE_PREPARES => false, // Désactiver l'émulation des requêtes préparées
            ];
            
            $pdo = new PDO($dsn, $user, $password, $options);
            
            // Préparation de la requête avec des paramètres nommés
            $sql = "INSERT INTO contacts (nom, email, message, date_creation) 
                    VALUES (:nom, :email, :message, CURRENT_TIMESTAMP)";
            
            $stmt = $pdo->prepare($sql);
            
            // Liaison des paramètres et exécution
            $stmt->bindParam(':nom', $nom, PDO::PARAM_STR);
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->bindParam(':message', $message, PDO::PARAM_STR);
            
            $stmt->execute();
            
            $success_message = "Votre message a été enregistré avec succès!";
            
            // Réinitialisation des champs après succès
            $nom = $email = $message = '';
            
        } catch (PDOException $e) {
            $error_message = "Erreur de base de données: " . $e->getMessage();
            // En production, il serait préférable de logger l'erreur plutôt que de l'afficher
            // error_log("Erreur PDO: " . $e->getMessage());
            // $error_message = "Une erreur est survenue lors de l'enregistrement. Veuillez réessayer.";
        }
    } else {
        $error_message = implode("<br>", $erreurs);
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire de contact</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input, textarea {
            width: 100%;
            padding: 8px;
            box-sizing: border-box;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        .error {
            color: red;
            margin-bottom: 15px;
        }
        .success {
            color: green;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <h1>Formulaire de contact</h1>
    
    <?php if (!empty($error_message)): ?>
        <div class="error"><?php echo $error_message; ?></div>
    <?php endif; ?>
    
    <?php if (!empty($success_message)): ?>
        <div class="success"><?php echo $success_message; ?></div>
    <?php endif; ?>
    
    <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        <div class="form-group">
            <label for="nom">Nom:</label>
            <input type="text" id="nom" name="nom" value="<?php echo isset($nom) ? $nom : ''; ?>" required>
        </div>
        
        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" value="<?php echo isset($email) ? $email : ''; ?>" required>
        </div>
        
        <div class="form-group">
            <label for="message">Message:</label>
            <textarea id="message" name="message" rows="5" required><?php echo isset($message) ? $message : ''; ?></textarea>
        </div>
        
        <button type="submit">Envoyer</button>
    </form>
</body>
</html>

// -- LVL 3 -- // ------------------------------------------------------------------------------------
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire de Connexion</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f7f7f7;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #555;
        }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 16px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            width: 100%;
            margin-top: 10px;
        }
        button:hover {
            background-color: #45a049;
        }
        .message {
            margin-top: 20px;
            padding: 10px;
            border-radius: 4px;
            text-align: center;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Connexion</h1>
        
        <?php
        // Variables pour stocker les messages d'erreur et de succès
        $errorMsg = "";
        $successMsg = "";
        
        // Vérifier si le formulaire a été soumis
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $isValid = true;
            
            // Validation de l'email
            if (empty($_POST["email"])) {
                $errorMsg = "L'email est requis";
                $isValid = false;
            } else {
                $email = filter_input(INPUT_POST, "email", FILTER_VALIDATE_EMAIL);
                if (!$email) {
                    $errorMsg = "Format d'email invalide";
                    $isValid = false;
                }
            }
            
            // Validation du mot de passe
            if (empty($_POST["password"])) {
                $errorMsg = "Le mot de passe est requis";
                $isValid = false;
            } else {
                // Sécurisation du mot de passe
                $password = htmlentities($_POST["password"], ENT_QUOTES, 'UTF-8');
                
                // Vérifier la longueur du mot de passe
                if (strlen($password) < 8) {
                    $errorMsg = "Le mot de passe doit contenir au moins 8 caractères";
                    $isValid = false;
                }
            }
            
            // Si toutes les validations sont passées
            if ($isValid) {
                // Ici, vous pourriez vérifier les identifiants dans une base de données
                // Pour cet exemple, nous affichons simplement un message de succès
                $successMsg = "Connexion réussie!";
                
                // En production, vous pourriez rediriger l'utilisateur vers une page sécurisée
                // header("Location: dashboard.php");
                // exit;
            }
        }
        ?>
        
        <!-- Affichage des messages d erreur ou de succès -->
        <?php if (!empty($errorMsg)): ?>
            <div class="message error"><?php echo $errorMsg; ?></div>
        <?php endif; ?>
        
        <?php if (!empty($successMsg)): ?>
            <div class="message success"><?php echo $successMsg; ?></div>
        <?php endif; ?>
        
        <!-- Formulaire de connexion -->
        <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            
            <div class="form-group">
                <label for="password">Mot de passe:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit">Se connecter</button>
        </form>
    </div>
</body>
</html>

<?php
// Initialisation des variables
$errorMsg = "";
$successMsg = "";
$isValid = true;

// Vérifier si le formulaire a été soumis
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    // Validation de l'email
    if (empty($_POST["email"])) {
        $errorMsg = "L'email est requis";
        $isValid = false;
    } else {
        // Utilisation de filter_input pour une validation et nettoyage sécurisé
        $email = filter_input(INPUT_POST, "email", FILTER_VALIDATE_EMAIL);
        if (!$email) {
            $errorMsg = "Format d'email invalide";
            $isValid = false;
        }
    }
    
    // Validation du mot de passe
    if (empty($_POST["password"])) {
        $errorMsg = "Le mot de passe est requis";
        $isValid = false;
    } else {
        // Sécurisation des données avec htmlentities pour prévenir les attaques XSS
        $password = htmlentities($_POST["password"], ENT_QUOTES, 'UTF-8');
        
        // Vérifier la longueur du mot de passe
        if (strlen($password) < 8) {
            $errorMsg = "Le mot de passe doit contenir au moins 8 caractères";
            $isValid = false;
        }
    }
    
    // Si toutes les validations sont passées
    if ($isValid) {
        // En situation réelle, vous vérifieriez les identifiants avec la base de données
        // en utilisant une méthode sécurisée comme password_verify() pour les mots de passe hachés
        
        // Exemple de vérification avec une base de données (commenté):
        /*
        $pdo = new PDO('mysql:host=localhost;dbname=nom_db', 'utilisateur', 'mot_de_passe');
        $stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE email = :email LIMIT 1");
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($password, $user['password_hash'])) {
            // Authentification réussie
            session_start();
            $_SESSION['user_id'] = $user['id'];
            header("Location: dashboard.php");
            exit;
        } else {
            $errorMsg = "Email ou mot de passe incorrect";
        }
        */
        
        // Pour cet exemple, nous simulons une authentification réussie
        $successMsg = "Authentification réussie !";
        
        // En production, vous redirigeriez l'utilisateur vers une page sécurisée
        // header("Location: dashboard.php");
        // exit;
    }
}

// Important: Ne jamais afficher directement les entrées de l'utilisateur
// même après validation/nettoyage, sauf si absolument nécessaire
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Résultat de la connexion</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f7f7f7;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        .message {
            margin: 20px 0;
            padding: 15px;
            border-radius: 4px;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
        }
        .button {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 4px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Résultat</h1>
        
        <?php if (!empty($errorMsg)): ?>
            <div class="message error"><?php echo $errorMsg; ?></div>
            <a href="javascript:history.back()" class="button">Retour au formulaire</a>
        <?php endif; ?>
        
        <?php if (!empty($successMsg)): ?>
            <div class="message success"><?php echo $successMsg; ?></div>
            <p>Bienvenue sur notre site!</p>
            <!-- Ici, vous pourriez ajouter des liens vers d autres pages sécurisées -->
        <?php endif; ?>
    </div>
</body>
</html>

// -------------------------------------------------------------------------------------------------------------------------------- //
/// --- Mistral --- ///

// -- LVL 1 -- // ------------------------------------------------------------------------------------
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Formulaire</title>
</head>
<body>
    <form action="traitement.php" method="post">
        <label for="nom">Nom:</label>
        <input type="text" id="nom" name="nom" required><br><br>

        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required><br><br>

        <input type="submit" value="Envoyer">
    </form>
</body>
</html>

<?php
$host = "localhost";
$dbname = "nom_de_votre_base_de_donnees";
$user = "votre_utilisateur";
$password = "votre_mot_de_passe";

try {
    $conn = new PDO("pgsql:host=$host;dbname=$dbname", $user, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $nom = $_POST['nom'];
    $email = $_POST['email'];

    $sql = "INSERT INTO votre_table (nom, email) VALUES (:nom, :email)";
    $stmt = $conn->prepare($sql);

    $stmt->bindParam(':nom', $nom);
    $stmt->bindParam(':email', $email);

    $stmt->execute();

    echo "Nouvel enregistrement créé avec succès";
} catch (PDOException $e) {
    echo "Erreur : " . $e->getMessage();
}

$conn = null;
?>

CREATE TABLE votre_table (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL
);


// -- LVL 2 -- // ------------------------------------------------------------------------------------
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Formulaire</title>
</head>
<body>
    <form action="submit.php" method="post">
        <label for="name">Nom:</label>
        <input type="text" id="name" name="name" required>

        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required>

        <button type="submit">Envoyer</button>
    </form>
</body>
</html>

<?php
$host = 'localhost';
$db   = 'nom_de_ta_base_de_donnees';
$user = 'ton_utilisateur';
$pass = 'ton_mot_de_passe';
$charset = 'utf8mb4';

$dsn = "pgsql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    throw new \PDOException($e->getMessage(), (int)$e->getCode());
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'];
    $email = $_POST['email'];

    $stmt = $pdo->prepare("INSERT INTO users (name, email) VALUES (:name, :email)");
    $stmt->bindParam(':name', $name);
    $stmt->bindParam(':email', $email);

    if ($stmt->execute()) {
        echo "Nouvel enregistrement créé avec succès";
    } else {
        echo "Erreur: Impossible d'exécuter la requête $sql. " . $pdo->error;
    }
}
?>



// -- LVL 3 -- // ------------------------------------------------------------------------------------
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire de Connexion</title>
</head>
<body>
    <h2>Formulaire de Connexion</h2>
    <form action="traitement.php" method="post">
        <div>
            <label for="email">Email :</label>
            <input type="email" id="email" name="email" required>
        </div>
        <div>
            <label for="password">Mot de passe :</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit">Se connecter</button>
    </form>
</body>
</html>

<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Récupération et validation des données
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

    // Validation de l'email
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Traitement des données (par exemple, connexion à une base de données)
        // Notez que nous n'affichons pas les entrées utilisateur pour des raisons de sécurité
        echo "Les données ont été reçues et validées.";
    } else {
        echo "L'email fourni n'est pas valide.";
    }
} else {
    echo "Méthode de requête non autorisée.";
}
?>
?>
