import razorpay
from django.conf import settings


def create_razorpay_plan_util(client, plan_data: dict):
    """
    Utility function to create a Razorpay plan.

    Args:
        plan_data (dict): The dictionary containing period, interval, and item info.

    Returns:
        dict: Response from Razorpay API if successful.

    Raises:
        Exception: If the Razorpay plan creation fails.
    """
    try:
        # client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        plan = client.plan.create(data=plan_data)
        return plan
    except Exception as e:
        raise Exception(f"Failed to create Razorpay plan: {str(e)}")
    




def create_school_fee_subscription(client, plan_id, customer_id, student_name, admission_year, total_months, monthly_fee_in_paise, one_time_fee_in_paise):
# def create_school_fee_subscription(client, plan_id: str,customer_id: str,student_name: str,admission_year: str,total_months: int = 12,monthly_fee_in_paise: int = 50000,one_time_fee_in_paise: int = 500000):
    """
    Creates a Razorpay subscription for a student with one-time addon fee.

    Args:
        plan_id (str): ID of the Razorpay plan.
        customer_id (str): Razorpay customer ID.
        student_name (str): Name of the student.
        admission_year (str): Admission year (e.g., "2025").
        total_months (int): Total months for the subscription. Default is 12.
        monthly_fee_in_paise (int): Monthly fee in paise. Default ₹500.
        one_time_fee_in_paise (int): One-time admission/dress fee in paise. Default ₹5000.

    Returns:
        dict: Razorpay subscription details or error message.
    """

    try:
        # client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))

        subscription_data = {
            "plan_id": plan_id,
            "total_count": total_months,
            "quantity": 1,
            "customer_notify": 1,
            "customer_id": customer_id,
            "notes": {
                "student_name": student_name,
                "admission_year": admission_year,
                "purpose": "school fee subscription"
            },
            "addons": [
                {
                    "item": {
                        "name": "Admission + Dress Fee",
                        "amount": one_time_fee_in_paise,
                        "currency": "INR"
                    }
                }
            ]
        }

        subscription = client.subscription.create(data=subscription_data)

        return subscription

    except Exception as e:
        return {"error": str(e)}


def create_customer(client, name, email, contact):
    customer = client.customer.create({
        "name": name,
        "email": email,
        "contact": contact
    })
    
    # 🔁 Save customer['id'] in your DB (e.g., MySQL, MongoDB, Django Model)
    # Example: user.razorpay_customer_id = customer['id']
    
    return customer['id']

def get_razorpay_plan(client, plan_id):
    """
    Retrieves a Razorpay plan by its ID.
    Args:
    """
    try:
        plan_details = client.plan.fetch(plan_id)
        # print("Plan Details:")
        print(plan_details)
    except Exception as e:
        print("Something went wrong:", e)


