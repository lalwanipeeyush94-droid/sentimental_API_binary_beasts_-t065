def generate_bola_evidence(
    url: str,
    order_id: str,
    owner: str,
    other_user: str,
    owner_status: int,
    other_user_status: int,
):

    confirmed = (
        owner_status == 200
        and other_user_status == 200
    )


    evidence = {

        "vulnerability_type": "BOLA",

        "endpoint": url,

        "resource_id": order_id,

        "owner_identity": owner,

        "owner_status": owner_status,

        "test_identity": other_user,

        "test_status": other_user_status,

        "authorization_contrast": {

            "owner": {

                "user": owner,

                "status": owner_status,

                "access": (
                    owner_status == 200
                ),
            },

            "other_user": {

                "user": other_user,

                "status": other_user_status,

                "access": (
                    other_user_status == 200
                ),
            },
        },

        "confirmed": confirmed,
    }


    if confirmed:

        evidence["result"] = (
            "BOLA CONFIRMED"
        )

        evidence["severity"] = "HIGH"

        evidence["description"] = (
            f"User '{other_user}' was able "
            f"to access resource '{order_id}', "
            f"which is owned by '{owner}'."
        )

    else:

        evidence["result"] = (
            "NO BOLA CONFIRMED"
        )

        evidence["severity"] = "INFO"

        evidence["description"] = (
            "The authorization test did "
            "not confirm BOLA."
        )


    return evidence