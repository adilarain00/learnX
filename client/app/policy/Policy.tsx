/* eslint-disable react/no-unescaped-entities */
import Client1 from "../../public/assests/hero-banner.png";
import { styles } from "../styles/style";
import Image from "next/image";
import React from "react";

type Props = {};

const Policy = (props: Props) => {
  return (
    <div className="w-[95%] 800px:w-[85%] m-auto">
      <div className={"py-2 text-black dark:text-white px-3"}>
        <h1 className={`${styles.title} !text-start pt-2`}>
          <span className="text-[#9e2828]">LearnX</span>'s Terms and Condition.
        </h1>
        <ul style={{ listStyle: "unset", marginLeft: "15px" }}>
          <p className="py-2 ml-[-15px] text-[16px] font-Poppins leading-8 whitespace-pre-line">
            By accessing and using{" "}
            <span className="text-[#9e2828]">LearnX</span>, you agree to comply
            with our platform’s terms and conditions. Our goal is to provide a
            seamless learning experience while maintaining a safe and respectful
            environment for all users. These terms outline the rights and
            responsibilities of both learners and{" "}
            <span className="text-[#9e2828]">LearnX</span> to ensure a smooth
            and productive experience.
          </p>
          <br />
          <p className="py-2 ml-[-15px] text-[16px] font-Poppins leading-8 whitespace-pre-line">
            All content, including courses, materials, and resources, is the
            intellectual property of{" "}
            <span className="text-[#9e2828]">LearnX</span> and its instructors.
            Users are granted access to these materials for personal learning
            purposes only. Unauthorized distribution, reproduction, or resale of
            any content is strictly prohibited and may result in account
            suspension.
          </p>
          <br />
          <p className="py-2 ml-[-15px] text-[16px] font-Poppins leading-8 whitespace-pre-line">
            To maintain a high standard of learning, users are expected to
            engage ethically in all activities on the platform. Any form of
            misconduct, including cheating, plagiarism, or fraudulent activity,
            will not be tolerated.{" "}
            <span className="text-[#9e2828]">LearnX</span> reserves the right to
            take action against accounts found violating our integrity policies.
          </p>
          <br />
          <p className="py-2 ml-[-15px] text-[16px] font-Poppins leading-8 whitespace-pre-line">
            By continuing to use <span className="text-[#9e2828]">LearnX</span>,
            you acknowledge and accept these terms. We encourage users to review
            our terms periodically, as{" "}
            <span className="text-[#9e2828]">LearnX</span> reserves the right to
            modify them when necessary. If you have any questions, our support
            team is always available to assist you.
          </p>
          <br />
          <p className="py-2 ml-[-15px] text-[16px] font-Poppins leading-8 whitespace-pre-line">
            Payments for premium courses or subscription plans are
            non-refundable unless otherwise stated. Users are responsible for
            ensuring their eligibility for specific courses before making a
            purchase. <span className="text-[#9e2828]">LearnX</span> may update
            pricing, course availability, or terms at any time, with prior
            notice to users.
          </p>
        </ul>
      </div>

      <div className="w-full 800px:flex items-center">
        <div className="800px:w-[50%] w-full">
          <Image src={Client1} alt="business" width={500} height={500} />
        </div>
        <div className="800px:w-[50%] w-full">
          <h3 className={`${styles.title} 800px:!text-[40px]`}>
            Empowering Learning, Ensuring Trust!
          </h3>
          <br />
          <p className={styles.label}>
            At <span className="text-[#9e2828]">LearnX</span>, we are dedicated
            to providing a secure, engaging, and high-quality learning
            experience for everyone. Our platform operates on trust, fairness,
            and innovation, ensuring that every learner gets the best out of
            their journey. Stay committed, stay curious, and grow with{" "}
            <span className="text-[#9e2828]">LearnX</span>! 🚀
          </p>
        </div>
        <br />
        <br />
      </div>
    </div>
  );
};

export default Policy;
