from fastapi import (
    FastAPI,
    Header,
    HTTPException
)


app = FastAPI(

    title=(
        "SentinelAPI Vulnerable Sandbox"
    ),

    description=(
        "Intentionally vulnerable "
        "API for BOLA testing"
    ),

    version="1.0.0",
)


orders = {

    "B204": {

        "owner": "alice",

        "product": "Laptop",

        "amount": 75000,
    },

    "B205": {

        "owner": "bob",

        "product": "Phone",

        "amount": 45000,
    },
}


@app.get("/")
def home():

    return {

        "message":
            "SentinelAPI Vulnerable Sandbox",

        "status":
            "running",
    }


@app.get(
    "/orders/{order_id}"
)
def get_order(

    order_id: str,

    x_user: str = Header(...)
):

    if order_id not in orders:

        raise HTTPException(

            status_code=404,

            detail="Order not found",
        )


    # INTENTIONALLY VULNERABLE:
    #
    # The API does not verify
    # whether x_user owns the order.

    return {

        "order_id":
            order_id,

        "owner":
            orders[order_id]["owner"],

        "product":
            orders[order_id]["product"],

        "amount":
            orders[order_id]["amount"],

        "requested_by":
            x_user,
    }