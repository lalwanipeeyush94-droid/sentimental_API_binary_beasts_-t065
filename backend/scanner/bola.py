import httpx

from scanner.evidence import (
    generate_bola_evidence
)


def test_bola(
    base_url: str,
    order_id: str,
    owner: str,
    other_user: str,
):

    url = (
        f"{base_url}/orders/{order_id}"
    )


    headers_owner = {
        "X-User": owner
    }


    headers_other = {
        "X-User": other_user
    }


    with httpx.Client() as client:

        owner_response = client.get(
            url,
            headers=headers_owner
        )

        other_response = client.get(
            url,
            headers=headers_other
        )


    bola_detected = (
        owner_response.status_code == 200
        and
        other_response.status_code == 200
    )


    evidence = (
        generate_bola_evidence(
            url=url,
            order_id=order_id,
            owner=owner,
            other_user=other_user,
            owner_status=(
                owner_response.status_code
            ),
            other_user_status=(
                other_response.status_code
            ),
        )
    )


    return {

        "url": url,

        "owner": owner,

        "other_user": other_user,

        "owner_status": (
            owner_response.status_code
        ),

        "other_user_status": (
            other_response.status_code
        ),

        "bola_detected": bola_detected,

        "evidence": evidence,
    }


if __name__ == "__main__":

    result = test_bola(
        base_url="http://127.0.0.1:8001",
        order_id="B204",
        owner="alice",
        other_user="bob",
    )


    print(
        "\n--- SentinelAPI BOLA Test ---"
    )

    print(result)


    if result["bola_detected"]:

        print(
            "\n🔴 BOLA CONFIRMED"
        )

    else:

        print(
            "\n🟢 No BOLA detected"
        )