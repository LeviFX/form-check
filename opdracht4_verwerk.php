<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Opdracht 4 Verwerk</title>
    <script src="https://kit.fontawesome.com/7c254fb8d3.js" crossorigin="anonymous"></script>
</head>
<body>
<?php

echo "<h2>Resultaat:</h2><br>";

if (isset($_POST['submit'])) {
    // Voer alle andere checks uit
    $naam = htmlentities($_POST["naam"], ENT_QUOTES);
    $leeftijd = htmlentities($_POST["leeftijd"], ENT_QUOTES);
    $email = htmlentities($_POST["email"], ENT_QUOTES);
    $wachtwoord = htmlentities($_POST["wachtwoord"], ENT_QUOTES);
    $postcode = htmlentities($_POST["postcode"], ENT_QUOTES);
    $koek = strtolower($_POST["koek"]);

    $SuccessCheck = 0;

    if (isset($_SERVER["HTTP_REFERER"]) && $_SERVER["HTTP_REFERER"] == "https://84845.ict-lab.nl/veipro/php/opdracht4/opdracht4_form.php") {
        // Afzender klopt
        session_start();
        $SuccessCheck++; // 1
        if (isset($_SESSION["token"]) && $_SESSION["token"] == $_POST["csrf_token"]) {
            // Token klopt
            $SuccessCheck++; // 2
            if (isset($naam, $leeftijd, $email, $wachtwoord, $postcode, $koek)) {
                $SuccessCheck++; // 3
                // Alle velden zijn ingevuld
                if (strlen($naam) > 0) {
                    // Iets ingevuld
                    if (preg_match ("/^[a-zA-z]*$/", $naam)) {
                        // Naam klopt
                        echo "Naam: " . $naam . " <i class='fas fa-check'></i><br>";
                        $SuccessCheck++; // 4
                    } else {
                        // Geen correcte letters
                        echo "Naam Error: Geen correcte tekens <i class='fas fa-times'></i> <br>";
                    }  
                } else {
                    // Niks ingevuld
                    echo "Naam Error: Niks ingevuld <i class='fas fa-times'></i> <br>";
                }
                if (is_numeric($leeftijd) && $leeftijd > 0 && $leeftijd <= 135) {
                    // Leeftijd klopt
                    $SuccessCheck++; // 5
                    echo "Leeftijd: " . $leeftijd . " <i class='fas fa-check'></i><br>";
                }  else {
                    // Voldoet niet aan leeftijd regels
                    echo "Leeftijd Error: Geen geldige leeftijd <i class='fas fa-times'></i> <br>";
                }
                if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    // Email klopt
                    $SuccessCheck++; // 6
                    echo "Email: " . $email . " <i class='fas fa-check'></i><br>";
                } else {
                    // Email klopt niet
                    echo "Email Error: Geen correcte tekens bij email gebruikt <i class='fas fa-times'></i> <br>";
                }
                if (strlen($wachtwoord) > 8) {
                    // Aantal klopt
                    if (preg_match("#[A-Z]+#", $wachtwoord)) {
                        // Volledig wachtwoord klopt
                        $SuccessCheck++; // 7
                        echo "Wachtwoord: " . $wachtwoord . " <i class='fas fa-check'></i><br>";
                    } else {
                        // Geen Hoofdletter
                        echo "Wachtwoord Error: Geen hoofdletters bij wachtwoord gebruikt <i class='fas fa-times'></i> <br>";
                    }
                } else {
                    // Wachtwoord minder dan 8 tekens
                    echo "Wachtwoord Error: Je moet minimaal 8 tekens gebruiken voor het wachtwoord <i class='fas fa-times'></i> <br>";
                }

                function PostcodeCheck($postcode) {
                    $remove = str_replace(" ","", $postcode);
                    $upper = strtoupper($remove);

                        if( preg_match("/^\W*[1-9]{1}[0-9]{3}\W*[a-zA-Z]{2}\W*$/",  $upper)) {
                        return $upper;
                        } else {
                        return false;
                    }
                }        
                if( PostcodeCheck($postcode) !== false ) {
                    $SuccessCheck++; // 8
                    echo "Postcode: " . $postcode . " <i class='fas fa-check'></i><br>";
                } else {
                    // Postcode klopt niet
                    echo "Postcode Error: Postcode is niet goed ingevult <i class='fas fa-times'></i> <br>";
                }
                if ($koek == "true" || $koek == "false") {
                    // Bool klopt
                    $SuccessCheck++; // 9
                    echo "Koek?: " . $koek . " <i class='fas fa-check'></i><br>";
                } else {
                    // Bool klopt niet
                    echo "Koek Error: De boolean klopt niet <i class='fas fa-times'></i> <br>";
                }
            } else {
                // Niet elk veld is ingevuld
                echo "Veld Error: Niet elk veld is ingevuld <i class='fas fa-times'></i> <br>";
            }
        } else {
            // Token klopt niet
            echo "Token Error: Token klopt niet <i class='fas fa-times'></i> <br>";
        }
    } else {
        // Data komt niet van de originele formulier
        echo "Formulier Error: Data komt niet van originele formulier <i class='fas fa-times'></i> <br>";
    }

    if ($SuccessCheck == 9) {
        // Database query uitvoeren
        require 'config.php';

        function uuidv4() {

            $data = openssl_random_pseudo_bytes(16);

            $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
            $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

            return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));

        }

        $id = uuidv4();

        if (strlen($id) < 35) { 
            // UUID creëren mislukt
            echo "ID Error: Er is iets fout gegaan bij het creëren van het ID <i class='fas fa-times'></i> <br>";

        } else {
            // UUID creëren goed gegaan

            $stmt = mysqli_prepare($mysqli, "INSERT INTO VeiPro (ID, Naam, Leeftijd, Email, Wachtwoord, Postcode, Koek) VALUES (?, ?, ?, ?, ?, ?, ?)");
            mysqli_stmt_bind_param($stmt, "ssissss", $id, $naam, $leeftijd, $email, sha1($wachtwoord), $postcode, $koek);
            mysqli_stmt_execute($stmt);

            echo "<br>Ingevoerd!<i class='fas fa-check'></i><br>";
            echo "<a href='opdracht4_form.php'>Terug gaan</a>";

        }
    
    } else {
        echo "<br>Succes Error: Het formulier is niet helemaal succesvol ingevuld. <i class='fas fa-times'></i> <br>";
        echo "<a href='opdracht4_form.php'>Terug gaan</a><br>";
    }

} else {
    // Niet op de submit knop gedrukt
    echo "Submit Error: Er is niet op de submit knop gedrukt <i class='fas fa-times'></i> <br>";
}
?>
</body>
</html>