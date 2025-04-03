/* eslint-disable react/no-unescaped-entities */
import React from "react";
import { styles } from "../styles/style";

import Image from "next/image";
import Client1 from "../../public/assests/hero-banner.png";

const About = () => {
  return (
    <div className="text-black dark:text-white">
      <br />
      <h1 className={`${styles.title} 800px:!text-[45px]`}>
        What is{" "}
        <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-600 to-blue-600">
          learning X Platform?
        </span>
      </h1>

      <br />
      <div className="w-[95%] 800px:w-[85%] m-auto">
        <p className="text-[18px] font-Poppins">
          <span className="text-[#9e2828]">LearnX</span> is a cutting-edge
          online learning platform designed to help students, professionals, and
          tech enthusiasts gain in-demand skills. With expertly curated courses,
          hands-on projects, and real-world applications,{" "}
          <span className="text-[#9e2828]">LearnX</span> ensures that learning
          is both engaging and effective.
          <br />
          <br />
          Our platform covers a wide range of topics, including web development,
          data science, artificial intelligence, and cybersecurity. Each course
          is structured to provide clear explanations, practical exercises, and
          interactive content that keeps learners motivated.
          <br />
          <br />
          At <span className="text-[#9e2828]">LearnX</span>, we believe in the
          power of experiential learning. That’s why we focus on project-based
          education, allowing students to build real applications while
          mastering new concepts. This approach bridges the gap between theory
          and practice, making learning more impactful.
          <br />
          <br />
          Whether you're a beginner looking to start your journey or an
          experienced professional aiming to upskill,{" "}
          <span className="text-[#9e2828]">LearnX</span> provides flexible
          learning paths tailored to your needs. Our platform adapts to
          different learning styles, ensuring that everyone can learn at their
          own pace.
          <br />
          <br />
          Join thousands of learners worldwide who trust{" "}
          <span className="text-[#9e2828]">LearnX</span> to elevate their
          careers. With an active community, expert instructors, and
          industry-relevant content,{" "}
          <span className="text-[#9e2828]">LearnX</span> is the ultimate
          destination for anyone looking to thrive in the digital world.
        </p>
        <br />
        <span className="text-[22px]">- Adil Arain</span>
        <h5 className="text-[18px] font-Poppins">Software Developer</h5>

        <div className="w-full 800px:flex items-center">
          <div className="800px:w-[50%] w-full">
            <Image src={Client1} alt="business" width={500} height={500} />
          </div>
          <div className="800px:w-[50%] w-full">
            <h3 className={`${styles.title} 800px:!text-[40px]`}>
              Transform Your Learning, Transform Your Future!
            </h3>
            <br />
            <p className={styles.label}>
              Unlock endless possibilities with{" "}
              <span className="text-[#9e2828]">LearnX</span>! Our platform
              empowers learners with the skills they need to succeed in today's
              fast-paced digital world. Explore expertly designed courses,
              engage in hands-on projects, and gain the confidence. Start
              learning today and take the next step toward your dream career! 🚀
            </p>
          </div>
          <br />
          <br />
        </div>
      </div>
    </div>
  );
};

export default About;
