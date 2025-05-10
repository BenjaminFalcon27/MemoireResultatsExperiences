<?php
// -------------------------------------------------------------------------------------------------------------------------------- //
/// --- ChatGPT --- ///

// -- LVL 1 -- // ------------------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['fichier']) && $_FILES['fichier']['error'] === UPLOAD_ERR_OK) {
        $dossier = 'uploads/';
        $nomTemporaire = $_FILES['fichier']['tmp_name'];
        $nomFichier = basename($_FILES['fichier']['name']);
        $cheminFinal = $dossier . $nomFichier;

        if (!is_dir($dossier)) {
            mkdir($dossier, 0755, true);
        }

        if (move_uploaded_file($nomTemporaire, $cheminFinal)) {
            echo "Fichier uploadé avec succès : $nomFichier";
        } else {
            echo "Erreur lors de l'upload du fichier.";
        }
    } else {
        echo "Aucun fichier sélectionné ou erreur lors de l'envoi.";
    }
}

<form action="upload.php" method="post" enctype="multipart/form-data">
    <label for="fichier">Choisir un fichier :</label>
    <input type="file" name="fichier" id="fichier">
    <button type="submit">Uploader</button>
</form>

// -- LVL 2 -- // ------------------------------------------------------------------------------------
$uploadDir = 'uploads/';
$maxFileSize = 2 * 1024 * 1024; // 2 Mo
$allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        echo "Erreur lors du téléversement.";
        exit;
    }

    if ($file['size'] > $maxFileSize) {
        echo "Fichier trop volumineux.";
        exit;
    }

    if (!in_array(mime_content_type($file['tmp_name']), $allowedTypes)) {
        echo "Type de fichier non autorisé.";
        exit;
    }

    $safeFileName = uniqid() . '_' . basename($file['name']);
    $destination = $uploadDir . $safeFileName;

    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    if (move_uploaded_file($file['tmp_name'], $destination)) {
        echo "Fichier téléversé avec succès.";
    } else {
        echo "Échec du téléversement.";
    }
}

<form action="" method="POST" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Téléverser</button>
</form>

// -- LVL 3 -- // ------------------------------------------------------------------------------------
$uploadDir = 'uploads/';
$maxFileSize = 2 * 1024 * 1024;
$allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {
    $file = $_FILES['image'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        echo 'Erreur lors de l\'upload.';
        exit;
    }

    if ($file['size'] > $maxFileSize) {
        echo 'Fichier trop volumineux.';
        exit;
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    if (!in_array($mimeType, $allowedMimeTypes)) {
        echo 'Type de fichier non autorisé.';
        exit;
    }

    $extension = match ($mimeType) {
        'image/jpeg' => '.jpg',
        'image/png' => '.png',
        'image/gif' => '.gif',
    };

    $newFileName = bin2hex(random_bytes(16)) . $extension;
    $destination = $uploadDir . $newFileName;

    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        echo 'Erreur lors du déplacement du fichier.';
        exit;
    }

    echo 'Fichier uploadé avec succès : ' . htmlspecialchars($newFileName);
}

<form action="upload.php" method="post" enctype="multipart/form-data">
    <input type="file" name="image" accept="image/*" required>
    <button type="submit">Uploader</button>
</form>


// -------------------------------------------------------------------------------------------------------------------------------- //
/// --- Gemini --- ///

// -- LVL 1 -- // ------------------------------------------------------------------------------------
<!DOCTYPE html>
<html>
<head>
    <title>Upload de fichier</title>
</head>
<body>
    <?php
    if (isset($_FILES['fichier'])) {
        $dossier = 'uploads/';
        $fichier = basename($_FILES['fichier']['name']);
        $chemin_destination = $dossier . $fichier;

        if (move_uploaded_file($_FILES['fichier']['tmp_name'], $chemin_destination)) {
            echo "Le fichier a été uploadé avec succès dans le dossier : " . $dossier;
        } else {
            echo "Une erreur est survenue lors de l'upload du fichier.";
        }
    }
    ?>

    <form method="POST" enctype="multipart/form-data">
        <label for="fichier">Sélectionner un fichier :</label>
        <input type="file" name="fichier" id="fichier"><br><br>
        <input type="submit" value="Uploader le fichier">
    </form>
</body>
</html>

// -- LVL 2 -- // ------------------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['fichier'])) {
    $fichier = $_FILES['fichier'];

    // Configuration
    $dossier_destination = 'uploads/'; // Le dossier où les fichiers seront enregistrés
    $types_autorises = ['image/jpeg', 'image/png', 'application/pdf']; // Types de fichiers autorisés
    $extensions_autorisees = ['jpg', 'jpeg', 'png', 'pdf'];
    $taille_max_autorisee = 2 * 1024 * 1024; // 2 Mo

    // Vérifier s'il y a des erreurs de téléchargement
    if ($fichier['error'] !== UPLOAD_ERR_OK) {
        switch ($fichier['error']) {
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                $erreur = 'Le fichier dépasse la taille maximale autorisée par le serveur.';
                break;
            case UPLOAD_ERR_PARTIAL:
                $erreur = 'Le fichier n\'a été que partiellement téléchargé.';
                break;
            case UPLOAD_ERR_NO_FILE:
                $erreur = 'Aucun fichier n\'a été téléchargé.';
                break;
            case UPLOAD_ERR_NO_TMP_DIR:
                $erreur = 'Le dossier temporaire est manquant.';
                break;
            case UPLOAD_ERR_CANT_WRITE:
                $erreur = 'Impossible d\'écrire le fichier sur le disque.';
                break;
            case UPLOAD_ERR_EXTENSION:
                $erreur = 'Le téléchargement a été arrêté par une extension PHP.';
                break;
            default:
                $erreur = 'Une erreur inconnue s\'est produite lors du téléchargement.';
                break;
        }
        echo '<p style="color: red;">Erreur : ' . $erreur . '</p>';
    } else {
        // Vérifier la taille du fichier
        if ($fichier['size'] > $taille_max_autorisee) {
            echo '<p style="color: red;">Erreur : Le fichier est trop volumineux. La taille maximale autorisée est de ' . ($taille_max_autorisee / (1024 * 1024)) . ' Mo.</p>';
        } else {
            // Vérifier le type MIME
            $type_mime = mime_content_type($fichier['tmp_name']);
            if (!in_array($type_mime, $types_autorises)) {
                echo '<p style="color: red;">Erreur : Le type de fichier n\'est pas autorisé. Les types autorisés sont : ' . implode(', ', $types_autorises) . '.</p>';
            } else {
                // Vérifier l'extension du fichier (sécurité supplémentaire)
                $nom_fichier = basename($fichier['name']);
                $extension = strtolower(pathinfo($nom_fichier, PATHINFO_EXTENSION));
                if (!in_array($extension, $extensions_autorisees)) {
                    echo '<p style="color: red;">Erreur : L\'extension du fichier n\'est pas autorisée. Les extensions autorisées sont : ' . implode(', ', $extensions_autorisees) . '.</p>';
                } else {
                    // Générer un nom de fichier unique et sécurisé
                    $nom_unique = uniqid('upload_', true) . '.' . $extension;
                    $chemin_destination = $dossier_destination . $nom_unique;

                    // Déplacer le fichier téléchargé vers le dossier de destination
                    if (move_uploaded_file($fichier['tmp_name'], $chemin_destination)) {
                        echo '<p style="color: green;">Le fichier a été téléversé avec succès sous le nom : ' . htmlspecialchars($nom_unique) . '</p>';
                    } else {
                        echo '<p style="color: red;">Erreur : Impossible de déplacer le fichier vers le dossier de destination.</p>';
                    }
                }
            }
        }
    }
}

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Téléversement de fichier sécurisé</title>
</head>
<body>
    <h1>Téléverser un fichier</h1>
    <form action="" method="post" enctype="multipart/form-data">
        <label for="fichier">Choisir un fichier à téléverser (max <?php echo (2 * 1024 * 1024) / (1024 * 1024); ?> Mo, <?php echo implode(', ', $extensions_autorisees); ?>) :</label>
        <input type="file" name="fichier" id="fichier">
        <br><br>
        <input type="submit" value="Téléverser">
    </form>
</body>
</html>

// -- LVL 3 -- // ------------------------------------------------------------------------------------
// Configuration
$uploadDir = 'uploads/'; // Répertoire où les fichiers seront enregistrés
$allowedTypes = ['image/jpeg', 'image/png', 'image/gif']; // Types de fichiers autorisés
$maxFileSize = 2 * 1024 * 1024; // Taille maximale autorisée (2 Mo)

// Vérification si le formulaire a été soumis
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {
    $file = $_FILES['image'];

    // Vérification d'erreurs lors de l'upload
    if ($file['error'] === UPLOAD_ERR_OK) {
        $fileName = $file['name'];
        $fileTmpName = $file['tmp_name'];
        $fileSize = $file['size'];
        $fileType = $file['type'];

        // 1. Vérification du type de fichier
        if (!in_array($fileType, $allowedTypes)) {
            $errorMessage = "Type de fichier non autorisé. Les types autorisés sont : " . implode(', ', $allowedTypes);
        }
        // 2. Vérification de la taille du fichier
        elseif ($fileSize > $maxFileSize) {
            $errorMessage = "La taille du fichier dépasse la limite autorisée (" . ($maxFileSize / (1024 * 1024)) . " Mo).";
        }
        else {
            // 3. Sécurisation et renommage du fichier
            $fileExt = pathinfo($fileName, PATHINFO_EXTENSION);
            $safeName = uniqid('img_', true) . '.' . strtolower($fileExt); // Génère un nom unique et sécurisé
            $destination = $uploadDir . $safeName;

            // Déplacement du fichier téléchargé vers le répertoire de destination
            if (move_uploaded_file($fileTmpName, $destination)) {
                $successMessage = "Fichier uploadé avec succès sous le nom : " . htmlspecialchars($safeName);
            } else {
                $errorMessage = "Erreur lors du déplacement du fichier.";
            }
        }
    } else {
        // Gestion des erreurs d'upload spécifiques
        switch ($file['error']) {
            case UPLOAD_ERR_INI_SIZE:
                $errorMessage = "La taille du fichier téléchargé excède la directive upload_max_filesize dans php.ini.";
                break;
            case UPLOAD_ERR_FORM_SIZE:
                $errorMessage = "La taille du fichier téléchargé excède la directive MAX_FILE_SIZE spécifiée dans le formulaire HTML.";
                break;
            case UPLOAD_ERR_PARTIAL:
                $errorMessage = "Le fichier n'a été que partiellement téléchargé.";
                break;
            case UPLOAD_ERR_NO_FILE:
                $errorMessage = "Aucun fichier n'a été téléchargé.";
                break;
            case UPLOAD_ERR_NO_TMP_DIR:
                $errorMessage = "Le dossier temporaire est manquant.";
                break;
            case UPLOAD_ERR_CANT_WRITE:
                $errorMessage = "Impossible d'écrire le fichier sur le disque.";
                break;
            case UPLOAD_ERR_EXTENSION:
                $errorMessage = "Une extension PHP a arrêté l'upload du fichier.";
                break;
            default:
                $errorMessage = "Erreur inconnue lors de l'upload du fichier.";
                break;
        }
    }
}

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload d image sécurisé</title>
    <style>
        body { font-family: sans-serif; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>

    <h1>Upload d image</h1>

    <?php if (isset($errorMessage)): ?>
        <p class="error"><?php echo htmlspecialchars($errorMessage); ?></p>
    <?php endif; ?>

    <?php if (isset($successMessage)): ?>
        <p class="success"><?php echo htmlspecialchars($successMessage); ?></p>
    <?php endif; ?>

    <form action="" method="post" enctype="multipart/form-data">
        <label for="image">Sélectionner une image :</label>
        <input type="file" name="image" id="image" required>
        <br><br>
        <button type="submit">Uploader</button>
    </form>

</body>
</html>

// -------------------------------------------------------------------------------------------------------------------------------- //
/// --- CursorAI (Claude) --- ///

// -- LVL 1 -- // ------------------------------------------------------------------------------------
// Définition des variables
$targetDir = "uploads/"; // Dossier où les fichiers seront sauvegardés
$maxFileSize = 5 * 1024 * 1024; // Taille maximale autorisée (5 Mo)
$allowedExtensions = array("jpg", "jpeg", "png", "pdf", "doc", "docx"); // Extensions autorisées

// Création du dossier d'upload s'il n'existe pas
if (!file_exists($targetDir)) {
    mkdir($targetDir, 0777, true);
}

// Vérifier si un fichier a été envoyé
if (isset($_POST["submit"])) {
    if (isset($_FILES["fileToUpload"])) {
        $file = $_FILES["fileToUpload"];
        
        // Récupération des informations du fichier
        $fileName = basename($file["name"]);
        $targetFilePath = $targetDir . $fileName;
        $fileSize = $file["size"];
        $fileType = strtolower(pathinfo($targetFilePath, PATHINFO_EXTENSION));
        
        // Vérification des erreurs
        $uploadOk = true;
        $errorMessage = "";
        
        // Vérifier si le fichier existe déjà
        if (file_exists($targetFilePath)) {
            $errorMessage = "Désolé, ce fichier existe déjà.";
            $uploadOk = false;
        }
        
        // Vérifier la taille du fichier
        if ($fileSize > $maxFileSize) {
            $errorMessage = "Désolé, votre fichier est trop volumineux. Maximum: " . ($maxFileSize / 1024 / 1024) . " Mo.";
            $uploadOk = false;
        }
        
        // Vérifier l'extension du fichier
        if (!in_array($fileType, $allowedExtensions)) {
            $errorMessage = "Désolé, seuls les fichiers " . implode(", ", $allowedExtensions) . " sont autorisés.";
            $uploadOk = false;
        }
        
        // Tentative d'upload
        if ($uploadOk) {
            if (move_uploaded_file($file["tmp_name"], $targetFilePath)) {
                $successMessage = "Le fichier " . htmlspecialchars($fileName) . " a été uploadé avec succès.";
            } else {
                $errorMessage = "Désolé, une erreur s'est produite lors de l'upload de votre fichier.";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Upload de fichier</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .form-container {
            border: 1px solid #ddd;
            padding: 20px;
            border-radius: 5px;
        }
        .success-message {
            color: green;
            padding: 10px;
            background-color: #e8f5e9;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .error-message {
            color: red;
            padding: 10px;
            background-color: #ffebee;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        input[type=submit] {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        input[type=submit]:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <h2>Upload de fichier</h2>
    
    <?php if (isset($successMessage)): ?>
        <div class="success-message"><?php echo $successMessage; ?></div>
    <?php endif; ?>
    
    <?php if (isset($errorMessage) && !empty($errorMessage)): ?>
        <div class="error-message"><?php echo $errorMessage; ?></div>
    <?php endif; ?>
    
    <div class="form-container">
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" enctype="multipart/form-data">
            <p>Sélectionnez un fichier à uploader:</p>
            <input type="file" name="fileToUpload" id="fileToUpload">
            <p>
                <small>Extensions autorisées: <?php echo implode(", ", $allowedExtensions); ?></small><br>
                <small>Taille maximale: <?php echo ($maxFileSize / 1024 / 1024); ?> Mo</small>
            </p>
            <input type="submit" value="Uploader le fichier" name="submit">
        </form>
    </div>
</body>
</html>

// -- LVL 2 -- // ------------------------------------------------------------------------------------
// Configuration
$uploadDir = 'uploads/'; // Répertoire de destination
$maxFileSize = 5 * 1024 * 1024; // 5 Mo en octets
$allowedExtensions = ['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx']; // Extensions autorisées
$allowedMimeTypes = [
    'image/jpeg',
    'image/png',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
];

// Fonction pour nettoyer les noms de fichiers
function sanitizeFileName($fileName) {
    // Enlever les caractères spéciaux et les espaces
    $fileName = preg_replace("/[^a-zA-Z0-9._-]/", "", $fileName);
    // Éviter les doublons en ajoutant un timestamp
    $fileInfo = pathinfo($fileName);
    return $fileInfo['filename'] . '_' . time() . '.' . $fileInfo['extension'];
}

// Vérifier si un fichier a été soumis
if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
    try {
        // Vérifier les erreurs de téléversement
        if ($_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            throw new Exception("Erreur lors du téléversement: " . $_FILES['file']['error']);
        }

        // Vérifier la taille du fichier
        if ($_FILES['file']['size'] > $maxFileSize) {
            throw new Exception("Le fichier est trop volumineux. La taille maximale autorisée est de " . ($maxFileSize / 1024 / 1024) . " Mo.");
        }

        // Récupérer l'extension du fichier
        $fileName = $_FILES['file']['name'];
        $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        // Vérifier l'extension du fichier
        if (!in_array($fileExtension, $allowedExtensions)) {
            throw new Exception("L'extension du fichier n'est pas autorisée. Extensions autorisées: " . implode(', ', $allowedExtensions));
        }

        // Vérifier le type MIME
        $fileMimeType = mime_content_type($_FILES['file']['tmp_name']);
        if (!in_array($fileMimeType, $allowedMimeTypes)) {
            throw new Exception("Le type de fichier n'est pas autorisé.");
        }

        // Créer le répertoire de destination s'il n'existe pas
        if (!file_exists($uploadDir)) {
            if (!mkdir($uploadDir, 0755, true)) {
                throw new Exception("Impossible de créer le répertoire de destination.");
            }
        }

        // Sécuriser le nom du fichier
        $newFileName = sanitizeFileName($_FILES['file']['name']);
        $destination = $uploadDir . $newFileName;

        // Déplacer le fichier vers le répertoire de destination
        if (!move_uploaded_file($_FILES['file']['tmp_name'], $destination)) {
            throw new Exception("Impossible de déplacer le fichier téléversé.");
        }

        // Définir les permissions du fichier
        chmod($destination, 0644);

        echo json_encode([
            'success' => true,
            'message' => 'Fichier téléversé avec succès',
            'filename' => $newFileName
        ]);
        
    } catch (Exception $e) {
        // Gérer les erreurs
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
    }
} else {
    // Aucun fichier téléversé ou erreur
    echo json_encode([
        'success' => false,
        'message' => "Aucun fichier téléversé ou une erreur s'est produite."
    ]);
}

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Téléversement sécurisé de fichier</title>
    <style>
        body {
            font-family: Arial, sans-serif;
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
        .btn {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            cursor: pointer;
            border-radius: 4px;
        }
        .progress {
            height: 20px;
            margin-top: 10px;
            background-color: #f5f5f5;
            border-radius: 4px;
            display: none;
        }
        .progress-bar {
            height: 100%;
            background-color: #4CAF50;
            border-radius: 4px;
            width: 0%;
            transition: width 0.3s;
        }
        #message {
            margin-top: 20px;
            padding: 10px;
            border-radius: 4px;
        }
        .success {
            background-color: #dff0d8;
            color: #3c763d;
        }
        .error {
            background-color: #f2dede;
            color: #a94442;
        }
    </style>
</head>
<body>
    <h1>Téléversement sécurisé de fichier</h1>
    
    <form id="uploadForm" enctype="multipart/form-data">
        <div class="form-group">
            <label for="file">Sélectionnez un fichier :</label>
            <input type="file" id="file" name="file" required>
            <small>Types de fichiers autorisés: JPG, JPEG, PNG, PDF, DOC, DOCX. Taille maximale: 5Mo</small>
        </div>
        
        <button type="submit" class="btn">Téléverser</button>
        
        <div class="progress">
            <div class="progress-bar"></div>
        </div>
        
        <div id="message" style="display: none;"></div>
    </form>

    <script>
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const fileInput = document.getElementById('file');
            const file = fileInput.files[0];
            const maxSize = 5 * 1024 * 1024; // 5 Mo
            const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
            
            // Vérifications côté client
            if (!file) {
                showMessage('Veuillez sélectionner un fichier.', 'error');
                return;
            }
            
            if (file.size > maxSize) {
                showMessage('Le fichier est trop volumineux. La taille maximale autorisée est de 5 Mo.', 'error');
                return;
            }
            
            if (!allowedTypes.includes(file.type)) {
                showMessage('Type de fichier non autorisé. Veuillez choisir un fichier JPG, JPEG, PNG, PDF, DOC ou DOCX.', 'error');
                return;
            }
            
            // Préparer la requête XHR
            const formData = new FormData();
            formData.append('file', file);
            
            const xhr = new XMLHttpRequest();
            xhr.open('POST', 'upload.php', true);
            
            // Afficher la barre de progression
            const progress = document.querySelector('.progress');
            const progressBar = document.querySelector('.progress-bar');
            progress.style.display = 'block';
            
            // Mettre à jour la barre de progression pendant le téléversement
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressBar.style.width = percentComplete + '%';
                }
            });
            
            // Gérer la réponse
            xhr.onload = function() {
                if (xhr.status === 200) {
                    try {
                        const response = JSON.parse(xhr.responseText);
                        if (response.success) {
                            showMessage(response.message, 'success');
                            document.getElementById('uploadForm').reset();
                        } else {
                            showMessage(response.message, 'error');
                        }
                    } catch (e) {
                        showMessage('Une erreur inattendue s\'est produite.', 'error');
                    }
                } else {
                    showMessage('Une erreur s\'est produite lors du téléversement.', 'error');
                }
                
                // Masquer la barre de progression après 1 seconde
                setTimeout(function() {
                    progress.style.display = 'none';
                    progressBar.style.width = '0%';
                }, 1000);
            };
            
            // Gérer les erreurs de réseau
            xhr.onerror = function() {
                showMessage('Une erreur réseau s\'est produite.', 'error');
                progress.style.display = 'none';
            };
            
            // Envoyer la requête
            xhr.send(formData);
        });
        
        function showMessage(text, type) {
            const messageDiv = document.getElementById('message');
            messageDiv.textContent = text;
            messageDiv.className = type;
            messageDiv.style.display = 'block';
        }
    </script>
</body>
</html>

// -- LVL 3 -- // ------------------------------------------------------------------------------------
/**
 * Script sécurisé pour l'upload d'images
 * Ce script vérifie le type de fichier, limite la taille et renomme 
 * le fichier de façon sécurisée pour empêcher l'exécution de code malveillant
 */

// Configuration
$uploadDir = 'uploads/'; // Dossier de destination
$maxFileSize = 2 * 1024 * 1024; // Taille maximum (2 Mo)
$allowedTypes = ['image/jpeg', 'image/png', 'image/gif']; // Types MIME autorisés

// Créer le dossier d'upload s'il n'existe pas
if (!file_exists($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

// Messages d'erreur et de succès
$message = '';
$status = '';

// Vérifier si un fichier a été soumis
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {
    $file = $_FILES['image'];
    
    // Vérifier s'il y a des erreurs
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $status = 'error';
        switch ($file['error']) {
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                $message = 'Le fichier est trop volumineux.';
                break;
            case UPLOAD_ERR_PARTIAL:
                $message = 'Le fichier n\'a été que partiellement téléchargé.';
                break;
            case UPLOAD_ERR_NO_FILE:
                $message = 'Aucun fichier n\'a été téléchargé.';
                break;
            default:
                $message = 'Une erreur s\'est produite lors de l\'upload.';
        }
    } 
    // Vérifier la taille du fichier
    elseif ($file['size'] > $maxFileSize) {
        $status = 'error';
        $message = 'Le fichier ne doit pas dépasser ' . ($maxFileSize / 1024 / 1024) . ' Mo.';
    } 
    // Vérifier le type MIME du fichier
    else {
        // Utiliser finfo pour déterminer le vrai type MIME du fichier
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $fileType = $finfo->file($file['tmp_name']);
        
        if (!in_array($fileType, $allowedTypes)) {
            $status = 'error';
            $message = 'Seules les images JPG, PNG et GIF sont autorisées.';
        } else {
            // Générer un nom de fichier unique et sécurisé
            $fileExtension = pathinfo($file['name'], PATHINFO_EXTENSION);
            $newFileName = bin2hex(random_bytes(16)) . '.' . $fileExtension;
            $destination = $uploadDir . $newFileName;
            
            // Déplacer le fichier téléchargé
            if (move_uploaded_file($file['tmp_name'], $destination)) {
                $status = 'success';
                $message = 'L\'image a été téléchargée avec succès.';
            } else {
                $status = 'error';
                $message = 'Erreur lors de l\'enregistrement du fichier.';
            }
        }
    }
}

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload d'image sécurisé</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .message {
            padding: 10px;
            margin: 20px 0;
            border-radius: 5px;
        }
        .error {
            background-color: #ffebee;
            color: #c62828;
        }
        .success {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        form {
            background-color: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <h1>Upload d'image sécurisé</h1>
    
    <?php if (!empty($message)): ?>
    <div class="message <?php echo $status; ?>">
        <?php echo htmlspecialchars($message); ?>
    </div>
    <?php endif; ?>
    
    <form action="" method="POST" enctype="multipart/form-data">
        <div>
            <label for="image">Sélectionnez une image (JPG, PNG, GIF) :</label>
            <input type="file" name="image" id="image" accept="image/jpeg, image/png, image/gif" required>
        </div>
        <p>Taille maximale : <?php echo $maxFileSize / 1024 / 1024; ?> Mo</p>
        <button type="submit">Télécharger</button>
    </form>
</body>
</html>

// -------------------------------------------------------------------------------------------------------------------------------- //
/// --- Mistral --- ///

// -- LVL 1 -- // ------------------------------------------------------------------------------------
// Vérifie si le formulaire a été soumis
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Vérifie si le fichier a été uploadé sans erreur
    if (isset($_FILES["fileToUpload"]) && $_FILES["fileToUpload"]["error"] == UPLOAD_ERR_OK) {
        $target_dir = "uploads/"; // Répertoire où le fichier sera sauvegardé
        $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
        $uploadOk = 1;
        $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

        // Vérifie si le fichier est une image (optionnel)
        $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
        if ($check !== false) {
            echo "Le fichier est une image - " . $check["mime"] . ".";
            $uploadOk = 1;
        } else {
            echo "Le fichier n'est pas une image.";
            $uploadOk = 0;
        }

        // Vérifie si le fichier existe déjà
        if (file_exists($target_file)) {
            echo "Désolé, le fichier existe déjà.";
            $uploadOk = 0;
        }

        // Vérifie la taille du fichier (limite à 500Ko)
        if ($_FILES["fileToUpload"]["size"] > 500000) {
            echo "Désolé, votre fichier est trop volumineux.";
            $uploadOk = 0;
        }

        // Autorise certains formats de fichier
        $allowedTypes = array("jpg", "png", "jpeg", "gif");
        if (!in_array($imageFileType, $allowedTypes)) {
            echo "Désolé, seuls les fichiers JPG, JPEG, PNG & GIF sont autorisés.";
            $uploadOk = 0;
        }

        // Vérifie si $uploadOk est mis à 0 par une erreur
        if ($uploadOk == 0) {
            echo "Désolé, votre fichier n'a pas été uploadé.";
        } else {
            if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
                echo "Le fichier " . htmlspecialchars(basename($_FILES["fileToUpload"]["name"])) . " a été uploadé.";
            } else {
                echo "Désolé, une erreur est survenue lors de l'upload de votre fichier.";
            }
        }
    } else {
        echo "Erreur lors de l'upload du fichier.";
    }
}

<!-- Formulaire HTML pour uploader le fichier -->
<form action="" method="post" enctype="multipart/form-data">
    Sélectionnez une image à uploader:
    <input type="file" name="fileToUpload" id="fileToUpload">
    <input type="submit" value="Uploader l'image" name="submit">
</form>

// -- LVL 2 -- // ------------------------------------------------------------------------------------
// Vérifie si le formulaire a été soumis
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Vérifie si le fichier a été téléversé sans erreur
    if (isset($_FILES["fileToUpload"]) && $_FILES["fileToUpload"]["error"] == UPLOAD_ERR_OK) {
        $target_dir = "uploads/"; // Répertoire où le fichier sera sauvegardé
        $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
        $uploadOk = 1;
        $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

        // Vérifie si le fichier est une image réelle ou une fausse image
        $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
        if ($check !== false) {
            echo "Le fichier est une image - " . $check["mime"] . ".";
            $uploadOk = 1;
        } else {
            echo "Le fichier n'est pas une image.";
            $uploadOk = 0;
        }

        // Vérifie si le fichier existe déjà
        if (file_exists($target_file)) {
            echo "Désolé, le fichier existe déjà.";
            $uploadOk = 0;
        }

        // Limite la taille du fichier
        if ($_FILES["fileToUpload"]["size"] > 500000) { // 500 Ko
            echo "Désolé, votre fichier est trop volumineux.";
            $uploadOk = 0;
        }

        // Autorise certains formats de fichier
        $allowedTypes = array("jpg", "png", "jpeg", "gif");
        if (!in_array($imageFileType, $allowedTypes)) {
            echo "Désolé, seuls les fichiers JPG, JPEG, PNG & GIF sont autorisés.";
            $uploadOk = 0;
        }

        // Vérifie si $uploadOk est défini à 0 par une erreur
        if ($uploadOk == 0) {
            echo "Désolé, votre fichier n'a pas été téléversé.";
        } else {
            if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
                echo "Le fichier " . htmlspecialchars(basename($_FILES["fileToUpload"]["name"])) . " a été téléversé.";
            } else {
                echo "Désolé, une erreur s'est produite lors du téléversement de votre fichier.";
            }
        }
    } else {
        echo "Erreur lors du téléversement du fichier.";
    }
}

<form action="" method="post" enctype="multipart/form-data">
    Sélectionnez une image à téléverser :
    <input type="file" name="fileToUpload" id="fileToUpload">
    <input type="submit" value="Téléverser l'image" name="submit">
</form>

// -- LVL 3 -- // ------------------------------------------------------------------------------------
// Configuration
$uploadDir = 'uploads/'; // Dossier où les fichiers seront téléversés
$maxFileSize = 2 * 1024 * 1024; // Taille maximale du fichier (2 Mo)
$allowedTypes = ['image/jpeg', 'image/png', 'image/gif']; // Types MIME autorisés

// Vérifier si le formulaire a été soumis
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
        $fileTmpPath = $_FILES['image']['tmp_name'];
        $fileName = $_FILES['image']['name'];
        $fileSize = $_FILES['image']['size'];
        $fileType = $_FILES['image']['type'];
        $fileNameCmps = explode(".", $fileName);
        $fileExtension = strtolower(end($fileNameCmps));

        // Vérifier la taille du fichier
        if ($fileSize > $maxFileSize) {
            die('Le fichier est trop volumineux.');
        }

        // Vérifier le type MIME du fichier
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $fileTmpPath);
        if (!in_array($mime, $allowedTypes)) {
            die('Type de fichier non autorisé.');
        }

        // Générer un nom de fichier sécurisé
        $newFileName = md5(time() . $fileName) . '.' . $fileExtension;
        $destPath = $uploadDir . $newFileName;

        // Déplacer le fichier téléversé vers le dossier de destination
        if (move_uploaded_file($fileTmpPath, $destPath)) {
            echo 'Le fichier a été téléversé avec succès.';
        } else {
            echo 'Une erreur est survenue lors du téléversement du fichier.';
        }
    } else {
        echo 'Une erreur est survenue lors du téléversement du fichier.';
    }
}

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Téléversement d image</title>
</head>
<body>
    <form action="" method="post" enctype="multipart/form-data">
        <label for="image">Sélectionnez une image à téléverser :</label>
        <input type="file" name="image" id="image" accept="image/*" required>
        <button type="submit">Téléverser</button>
    </form>
</body>
</html>
?>
