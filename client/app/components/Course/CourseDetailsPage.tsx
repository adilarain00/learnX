import { useGetCourseDetailsQuery } from "@/redux/features/courses/courseApi";
import { useLoadUserQuery } from "@/redux/features/api/apiSlice";
import React, { useEffect, useState } from "react";
import { loadStripe } from "@stripe/stripe-js";

import {
  useCreatePaymentIntentMutation,
  useGetStripePublishablekeyQuery,
} from "@/redux/features/orders/ordersApi";

import Loader from "../Loader/Loader";
import Heading from "@/app/utils/Heading";
import Header from "../Header";
import Footer from "../Footer";
import CourseDetails from "./CourseDetails";



type Props = {
  id: string;
};

const CourseDetailsPage = ({ id }: Props) => {
  const [open, setOpen] = useState(false);
  const [route, setRoute] = useState("Login");
  const { data, isLoading, error } = useGetCourseDetailsQuery(id);
  const { data: config } = useGetStripePublishablekeyQuery({});
  const [createPaymentIntent, { data: paymentIntentData }] = useCreatePaymentIntentMutation();
  const { data: userData } = useLoadUserQuery(undefined, {});
  const [stripePromise, setStripePromise] = useState<any>(null);
  const [clientSecret, setClientSecret] = useState("");

  useEffect(() => {
    console.log("Fetched course data:", data);
    console.log("Error fetching course:", error);
    console.log("Course ID:", id);
  
    if (!data?.course) {
      console.log("Loading course details...");
      return;
    }
  
    if (config?.publishablekey) {
      setStripePromise(loadStripe(config.publishablekey));
    }
  
    if (data?.course && userData?.user) {
      const amount = Math.round(data.course.price * 100);
      createPaymentIntent(amount);
    }
  }, [config, createPaymentIntent, data?.course, userData, error, data, id]);
  

  if (isLoading) return <Loader />;
  if (error) {
    console.error("Error fetching course details:", error);
    return <div>Error loading course details. Please try again.</div>;
  }

  return (
    <div>
      <Heading
        title={`${data?.course?.name || "Loading"} - LearnX`}
        description="LearnX is a platform for students to learn and get help from teachers"
        keywords={data?.course?.tags || []}
      />
      <Header open={open} setOpen={setOpen} activeItem={1} setRoute={setRoute} route={route} />
      {stripePromise && (
        <CourseDetails
          data={data.course}
          stripePromise={stripePromise}
          clientSecret={clientSecret}
          setRoute={setRoute}
          setOpen={setOpen}
        />
      )}
      <Footer />
    </div>
  );
};

export default CourseDetailsPage;