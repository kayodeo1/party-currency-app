import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "react-hot-toast";
import DashboardSidebar from "@/components/DashboardSidebar";
import DashboardHeader from "@/components/DashboardHeader";
import { EventSuccessModal } from "@/components/events/EventSuccessModal";
import { EventForm } from "@/components/events/EventForm";
import { useAuthenticated } from "@/lib/hooks";
import { LoadingDisplay } from "@/components/LoadingDisplay";
import { BASE_URL } from "@/config";
import { getAuth } from "@/lib/util";

export default function CreateEvent() {
  const navigate = useNavigate();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [eventId, setEventId] = useState("");
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const authenticated = useAuthenticated();

  const [formData, setFormData] = useState({
    event_name: "",
    event_type: "",
    start_date: "",
    end_date: "",
    street_address: "",
    state: "",
    city: "",
    post_code: "",
    LGA: "",
    reconciliation_service: false,
  });

  useEffect(() => {
    const handleSidebarStateChange = (event) => {
      setSidebarCollapsed(event.detail.isCollapsed);
    };

    window.addEventListener('sidebarStateChange', handleSidebarStateChange);
    return () => {
      window.removeEventListener('sidebarStateChange', handleSidebarStateChange);
    };
  }, []);

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);

    try {
      const { accessToken } = getAuth();

      // Transform the data for the API
      const requestData = {
        ...formData,
        LGA: formData.LGA.toUpperCase(),
        reconciliation_service: Boolean(formData.reconciliation_service),
      };

      const response = await fetch(`${BASE_URL}/events/create`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Token ${accessToken}`,
        },
        body: JSON.stringify(requestData),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "Failed to create event");
      }

      setEventId(data.event.event_id);
      setShowSuccessModal(true);
      toast.success("Event created successfully!");
      navigate("/manage-event");
    } catch (error) {
      toast.error(error.message || "Failed to create event");
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!authenticated) {
    return <LoadingDisplay />;
  }

  return (
    <div className="bg-white min-h-screen">
      <DashboardSidebar
        isOpen={isMobileMenuOpen}
        onClose={() => setIsMobileMenuOpen(false)}
      />
      <div className={`transition-all duration-300 ${
        sidebarCollapsed ? "lg:pl-20" : "lg:pl-64"
      }`}>
        <DashboardHeader
          toggleMobileMenu={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        />
        <main className="flex-1 mx-auto p-4 md:p-8 w-full max-w-4xl">
          <h1 className="mb-8 font-playfair font-semibold text-2xl text-left">
            Create Event
          </h1>
          <EventForm
            formData={formData}
            handleInputChange={handleInputChange}
            handleSubmit={handleSubmit}
            isSubmitting={isSubmitting}
          />
        </main>
      </div>

      {showSuccessModal && (
        <EventSuccessModal
          eventId={eventId}
          onClose={() => setShowSuccessModal(false)}
          onNavigate={() => navigate("/templates")}
        />
      )}
    </div>
  );
}
