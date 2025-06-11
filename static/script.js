function generatePassword() {
    $.get("/generate?length=16", function(data) {
        $("#generated").text("Mot de passe : " + data.password);
    });
}

function reveal(id) {
    const pwElement = $("#pw-" + id);
    const isVisible = pwElement.data("visible");

    if (isVisible) {
        pwElement.text("");
        pwElement.data("visible", false);
    } else {
        $.get("/reveal/" + id)
            .done(function(data) {
                if (data.password) {
                    pwElement.text("Mot de passe : " + data.password);
                    pwElement.data("visible", true);
                } else if (data.error) {
                    pwElement.text("Erreur : " + data.error);
                }
            })
            .fail(function() {
                pwElement.text("Erreur lors du chargement.");
            });
    }
}

function share(id) {
    $.get("/share/" + id, function(data) {
        if (data.share_url) {
            alert("Lien de partage : " + data.share_url);
        } else {
            alert("Erreur : " + data.error);
        }
    });
}

function copyPassword(id) {
    const pwText = $("#pw-" + id).text().replace("Mot de passe : ", "");
    if (!pwText) return alert("Rien à copier !");

    navigator.clipboard.writeText(pwText).then(() => {
        alert("Mot de passe copié !");
    });
}
