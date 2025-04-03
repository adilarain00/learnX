import { useGetHeroDataQuery } from "@/redux/features/layout/layoutApi";
import React, { useEffect, useState } from "react";
import { HiMinus, HiPlus } from "react-icons/hi";
import { styles } from "@/app/styles/style";

type Props = {};

// Local FAQ Data (Displayed if API fails)
const localFAQs = [
  {
    _id: "1",
    question: "What is LearnX?",
    answer:
      "LearnX is an online learning platform designed to help students connect with experienced instructors. We offer various courses to enhance your knowledge in different domains.",
  },
  {
    _id: "2",
    question: "How do I enroll in a course?",
    answer:
      "You can enroll by signing up, browsing our course catalog, and selecting the course of your choice. Once enrolled, you’ll get full access to the course materials and resources.",
  },
  {
    _id: "3",
    question: "Is there a refund policy?",
    answer:
      "Yes! We offer a 7-day refund policy. If you are not satisfied with the course, you can request a refund within 7 days of purchase.",
  },
  {
    _id: "4",
    question: "Can I access courses on multiple devices?",
    answer:
      "Absolutely! You can access your courses on your laptop, tablet, or mobile device anytime, anywhere, as long as you are logged into your account.",
  },
  {
    _id: "5",
    question: "Do I get a certificate after completing a course?",
    answer:
      "Yes! After successfully completing a course, you will receive a certificate of completion that you can share on your resume or LinkedIn profile.",
  },
];

const FAQ = (props: Props) => {
  const { data } = useGetHeroDataQuery("FAQ", {});
  const [activeQuestion, setActiveQuestion] = useState<string | null>(null);
  const [questions, setQuestions] = useState(localFAQs);

  useEffect(() => {
    console.log("API Response:", data); // Debugging
    if (data?.layout?.faq) {
      setQuestions([...localFAQs, ...data.layout.faq]); // Merge local and API FAQs
    }
  }, [data]);

  const toggleQuestion = (id: string) => {
    setActiveQuestion(activeQuestion === id ? null : id);
  };

  return (
    <>
      <br />
      <div className="w-[90%] 800px:w-[75%] mx-auto">
        <h1
          className={`${styles.title} text-center text-[26px] 800px:text-[34px] font-semibold`}
        >
          Frequently Asked Questions
        </h1>
        <div className="mt-10">
          <dl className="space-y-5">
            {questions.map((q) => (
              <div key={q._id} className="border-b border-gray-300 pb-4">
                <dt>
                  <button
                    className="flex justify-between w-full text-left items-center text-lg 800px:text-xl font-medium text-black dark:text-white py-2 transition-all duration-300 ease-in-out"
                    onClick={() => toggleQuestion(q._id)}
                  >
                    <span>{q.question}</span>
                    <span className="ml-4">
                      {activeQuestion === q._id ? (
                        <HiMinus className="h-5 w-5 text-black dark:text-white" />
                      ) : (
                        <HiPlus className="h-5 w-5 text-black dark:text-white" />
                      )}
                    </span>
                  </button>
                </dt>
                {activeQuestion === q._id && (
                  <dd className="mt-3 mb-3 text-[23px] 800px:text-base font-normal text-gray-700 dark:text-gray-300 transition-all duration-300 ease-in-out">
                    {q.answer}
                  </dd>
                )}
              </div>
            ))}
          </dl>
        </div>
        <br />
        <br />
        <br />
        <br />
      </div>
    </>
  );
};

export default FAQ;
